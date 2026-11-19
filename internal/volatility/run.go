package volatility

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout   = 15 * time.Minute
	defaultMaxOutput = 64 << 20
	maxLogBytes      = 2 << 20
	logTailBytes     = 4 << 10
	statusOversized  = "oversized"
)

var (
	reCompleted = regexp.MustCompile(`Module (\S+) completed in ([0-9.]+) seconds`)
	reFailure   = regexp.MustCompile(`!--- Error running module (\S+): (.*)`)
)

// Runner executes the wrapper with a fixed argument list.
type Runner struct {
	cfg Config
}

// New returns a Runner. Config is validated at Run time so a server can be
// built without Volatility installed.
func New(cfg Config) *Runner {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxOutput <= 0 {
		cfg.MaxOutput = defaultMaxOutput
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.WorkRoot == "" {
		cfg.WorkRoot = os.TempDir()
	}
	return &Runner{cfg: cfg}
}

// Run analyzes one image. Per-plugin failures are reported in the Report; the
// error is reserved for infrastructure failures (missing executable, a
// timeout, a cancelled context). A report may be returned together with an
// error when a run timed out, so partial outputs can still be recorded.
func (r *Runner) Run(ctx context.Context, in Input) (*Report, []PluginOutput, error) {
	cfg := r.cfg
	if cfg.VolPath == "" || cfg.WrapperPath == "" {
		return nil, nil, errors.New("volatility analysis is not configured (set -volatility and -vol-wrapper)")
	}
	if len(cfg.Plugins) == 0 {
		return nil, nil, errors.New("volatility plugin list is empty")
	}
	if in.ImagePath == "" {
		return nil, nil, errors.New("volatility image path is empty")
	}
	if info, err := os.Stat(in.ImagePath); err != nil || !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("memory image is not a readable file: %w", err)
	}
	for _, dir := range []string{cfg.WorkRoot, cfg.SymbolsDir, cfg.CacheDir} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, nil, fmt.Errorf("create analysis directory: %w", err)
		}
	}
	work, err := os.MkdirTemp(cfg.WorkRoot, "vol-"+safeComponent(in.JobID)+"-")
	if err != nil {
		return nil, nil, fmt.Errorf("create analysis workdir: %w", err)
	}
	defer os.RemoveAll(work)

	pluginsFile := filepath.Join(work, "plugins.txt")
	if err := os.WriteFile(pluginsFile, []byte(strings.Join(cfg.Plugins, "\n")+"\n"), 0600); err != nil {
		return nil, nil, fmt.Errorf("write plugin list: %w", err)
	}

	var notes []string
	volArgs := ""
	if cfg.SymbolsDir != "" {
		volArgs = "-s " + cfg.SymbolsDir
	}
	if cfg.CacheDir != "" {
		if volArgs != "" {
			volArgs += " "
		}
		volArgs += "--cache-path " + cfg.CacheDir
	}
	args := []string{
		"-p", cfg.VolPath,
		"-i", in.ImagePath,
		"-m", pluginsFile,
		"-o", work,
		"-r", "jsonl",
		"--no-stats",
	}
	if volArgs != "" {
		args = append(args, "--vol-args", volArgs)
	}

	exe := cfg.WrapperPath
	if cfg.CPUs != "" && runtime.GOOS != "windows" {
		if taskset, lookErr := exec.LookPath("taskset"); lookErr == nil {
			exe = taskset
			args = append([]string{"-c", cfg.CPUs, cfg.WrapperPath}, args...)
		} else {
			notes = append(notes, "taskset is unavailable; Volatility ran with its default parallelism")
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	cmd := exec.CommandContext(callCtx, exe, args...)
	cmd.Dir = work
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"LANG=C.UTF-8",
	}
	log := &tailBuffer{limit: maxLogBytes}
	cmd.Stdout = log
	cmd.Stderr = log
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = 10 * time.Second

	runErr := cmd.Run()
	if runErr != nil && cmd.ProcessState == nil {
		return nil, nil, fmt.Errorf("start volatility wrapper: %w", runErr)
	}
	timedOut := errors.Is(callCtx.Err(), context.DeadlineExceeded)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if timedOut {
		notes = append(notes, fmt.Sprintf("analysis timed out after %s", cfg.Timeout))
	}

	durations, failures := parseWrapperLog(log.String())
	report := &Report{
		SchemaVersion: 1,
		JobID:         in.JobID,
		HostID:        in.HostID,
		GeneratedAt:   cfg.Now().UTC(),
		Engine: Engine{
			Name:          "volatility3",
			Version:       DefaultEngineVersion,
			WrapperCommit: DefaultWrapperCommit,
		},
		Image: in.Image,
	}
	notes = append(notes,
		"analysis output is derived evidence; the memory image itself is unchanged",
	)
	logText := log.String()
	if strings.Contains(logText, "translation layer requirement was not fulfilled") ||
		strings.Contains(logText, "Unable to validate the plugin requirements") {
		notes = append(notes, "the image has no usable Windows kernel layer; capture it with winpmem-physical (-1) or another acquisition tool")
	}
	report.Notes = append(report.Notes, notes...)
	report.LogTail = tailString(logText, logTailBytes)

	base := filepath.Base(in.ImagePath)
	var outputs []PluginOutput
	for _, plugin := range cfg.Plugins {
		result := PluginResult{Name: plugin, DurationMS: durations[plugin]}
		path := filepath.Join(work, base+"_"+plugin+".jsonl")
		info, statErr := os.Stat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			result.Status = StatusFailed
			result.Error = failures[plugin]
			if result.Error == "" {
				result.Error = "no output file was produced"
			}
			report.Plugins = append(report.Plugins, result)
			continue
		}
		result.Size = info.Size()
		if info.Size() > cfg.MaxOutput {
			result.Status = statusOversized
			result.Error = fmt.Sprintf("output is %d bytes, above the %d byte limit", info.Size(), cfg.MaxOutput)
			report.Plugins = append(report.Plugins, result)
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			result.Status = StatusFailed
			result.Error = readErr.Error()
			report.Plugins = append(report.Plugins, result)
			continue
		}
		result.Status = StatusCompleted
		result.Rows = countRows(data)
		report.Plugins = append(report.Plugins, result)
		outputs = append(outputs, PluginOutput{Name: plugin, Data: data, Rows: result.Rows, Size: int64(len(data))})
	}
	report.Summary = Summarize(report.Plugins)

	if timedOut {
		return report, outputs, fmt.Errorf("analysis timed out after %s", cfg.Timeout)
	}
	return report, outputs, nil
}

// parseWrapperLog extracts per-plugin durations and errors. The wrapper writes
// both progress and failures to stdout, so one pass is enough.
func parseWrapperLog(text string) (durations map[string]int64, failures map[string]string) {
	durations = map[string]int64{}
	failures = map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if m := reCompleted.FindStringSubmatch(line); m != nil {
			seconds, err := strconv.ParseFloat(m[2], 64)
			if err == nil {
				durations[m[1]] = int64(seconds * 1000)
			}
			continue
		}
		if m := reFailure.FindStringSubmatch(line); m != nil {
			failures[m[1]] = strings.TrimSpace(m[2])
		}
	}
	return durations, failures
}

func countRows(data []byte) int {
	if len(bytes.TrimSpace(data)) == 0 {
		return 0
	}
	n := 0
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) > 0 {
			n++
		}
	}
	return n
}

func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func safeComponent(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 60 {
			break
		}
	}
	if b.Len() == 0 {
		return "job"
	}
	return b.String()
}

// tailBuffer keeps the last limit bytes written, with a mutex because stdout
// and stderr are copied by two goroutines.
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.limit {
		b.buf = b.buf[len(b.buf)-b.limit:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
