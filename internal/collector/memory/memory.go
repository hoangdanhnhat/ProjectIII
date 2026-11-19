// Package memory implements the memory.v1 scenario: a full physical-memory
// image captured by an operator-supplied, hash-pinned acquisition binary
// (WinPmem on Windows) plus a schema-versioned manifest.
//
// # Subprocess policy
//
// This scenario runs the second subprocess in the codebase (the first is
// wevtutil in eventlog). The same rules apply, with one addition because the
// binary is not an OS component:
//
//   - The binary is never downloaded or written at runtime. The operator
//     places it on the endpoint and passes -memory-tool with an absolute,
//     clean path; -memory-tool-sha256 pins its digest and the agent re-checks
//     the digest before every capture.
//   - Arguments are fixed by the tool profile in profile.go. No shell and no
//     cmd.exe are involved; the only host-derived value in argv is the output
//     path, which the collector generates inside -memory-out.
//   - The output file is created only under -memory-out, read back through a
//     no-symlink open, hashed, uploaded, and removed unless -memory-keep.
//
// # Evidence handling
//
// A memory image is the most sensitive artifact this system can hold. The
// agent refuses to start a capture without elevation and enough free disk
// space, enforces a hard size and time budget, and records the tool digest,
// argv, image size and image SHA-256 in the manifest so the chain of custody
// is auditable. job.Since is not applicable: the image is a point-in-time
// snapshot of a live system, not an event-log window.
package memory

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// DefaultMaxBytes bounds one image when the agent does not configure a limit.
// It must match the server's -max-memory-image.
const DefaultMaxBytes int64 = 16 << 30 // 16 GiB

// DefaultTimeout bounds one acquisition run.
const DefaultTimeout = time.Hour

// minFreeHeadroom is reserved on top of physical memory for the image file,
// the manifest and the uploader's own needs.
const minFreeHeadroom = 256 << 20

// Probe describes the host state that decides whether a capture can start.
// It is injectable so the orchestration stays testable off Windows.
type Probe struct {
	TotalMemory int64
	FreeDisk    int64
	Elevated    bool
}

// RunResult is one completed or failed tool invocation.
type RunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Options configures the scenario.
type Options struct {
	ToolPath    string // absolute path to the acquisition binary
	ToolSHA256  string // pinned digest; required with ToolPath
	ToolName    string // profile: winpmem or winpmem-mini (empty: derive from path)
	ToolVersion string // recorded in the manifest; never executed
	OutDir      string // staging directory for the image
	MaxBytes    int64
	Timeout     time.Duration
	Keep        bool // keep the local image after a successful upload

	// Injectable dependencies for tests.
	Probe func(outDir string) (Probe, error)
	Run   func(ctx context.Context, exe string, args []string) RunResult
	Now   func() time.Time
}

// New returns the memory.v1 collector.
func New(o Options) collector.Collector {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &scenario{opts: o}
}

type scenario struct {
	opts Options
}

func (s *scenario) ID() string          { return protocol.ScenarioMemory }
func (s *scenario) Platforms() []string { return []string{"windows"} }

func (s *scenario) Collect(ctx context.Context, job *protocol.Job, sink collector.Sink) error {
	o := s.opts
	if o.ToolPath == "" || o.ToolSHA256 == "" || o.OutDir == "" {
		return fmt.Errorf("%w: -memory-tool, -memory-tool-sha256 and -memory-out are required for memory.v1", collector.ErrNeedsConfig)
	}
	if !filepath.IsAbs(o.ToolPath) || filepath.Clean(o.ToolPath) != o.ToolPath {
		return fmt.Errorf("%w: -memory-tool must be a clean absolute path", collector.ErrNeedsConfig)
	}
	prof, err := lookupProfile(o.ToolName, o.ToolPath)
	if err != nil {
		return fmt.Errorf("%w: %v", collector.ErrNeedsConfig, err)
	}
	if err := VerifyTool(o.ToolPath, o.ToolSHA256); err != nil {
		return fmt.Errorf("%w: %v", collector.ErrNeedsConfig, err)
	}
	if info, err := os.Stat(o.OutDir); err != nil || !info.IsDir() {
		return fmt.Errorf("%w: -memory-out must name an existing directory", collector.ErrNeedsConfig)
	}
	probe, err := s.probe(o.OutDir)
	if err != nil {
		sink.Problem("memory capture preflight: %v", err)
		return nil
	}
	if err := preflight(probe, o.MaxBytes); err != nil {
		sink.Problem("memory capture preflight: %v", err)
		return nil
	}
	if job.Since != nil {
		sink.Note("job since ignored: a memory image is a point-in-time capture")
	}

	path, reused := findCapture(o.OutDir, job.HostID, job.ID, prof.ext)
	started := s.opts.Now()
	var run RunResult
	if reused {
		sink.Note("reusing capture from an earlier attempt: %s", path)
	} else {
		path = filepath.Join(o.OutDir, captureName(job.HostID, job.ID, prof.ext, started))
		run = s.run(ctx, o.ToolPath, prof.args(path))
		if ctx.Err() != nil {
			// Shutdown or cancellation: discard the partial image and leave
			// the job running for a retry rather than reporting a failure or
			// uploading a truncated capture.
			_ = os.Remove(path)
			return ctx.Err()
		}
		if run.Err != nil {
			if prof.okExit != nil && prof.okExit(run.ExitCode) {
				// WinPmem returns 1 after a completed acquisition; the code
				// stays in the manifest as evidence of the tool's convention.
				run.Err = nil
			} else {
				_ = os.Remove(path)
				if err := s.uploadManifest(sink, job, prof, path, nil, probe, started, run); err != nil {
					return err
				}
				sink.Problem("capture tool %s failed: %v", prof.name, run.Err)
				return nil
			}
		}
	}

	image, err := inspectImage(path, o.MaxBytes)
	if err != nil {
		_ = os.Remove(path)
		run.Err = err
		if uploadErr := s.uploadManifest(sink, job, prof, path, nil, probe, started, run); uploadErr != nil {
			return uploadErr
		}
		sink.Problem("memory image check failed: %v", err)
		return nil
	}
	manifest := s.manifest(job, prof, path, image, probe, started, run)
	if err := sink.File(protocol.KindMemoryImage, path,
		"full physical memory image captured with "+prof.name); err != nil {
		return err // transport error: retry reuses the staged image
	}
	if err := sink.Bytes(protocol.KindMemoryManifest, "memory_capture.json",
		"memory capture manifest: tool identity, image hash and capture result", Render(manifest)); err != nil {
		return err
	}
	if o.Keep {
		sink.Note("kept local memory image at %s", path)
	} else if err := os.Remove(path); err != nil {
		sink.Note("could not remove local memory image %s: %v", path, err)
	}
	return nil
}

func (s *scenario) probe(dir string) (Probe, error) {
	if s.opts.Probe != nil {
		return s.opts.Probe(dir)
	}
	return probeHost(dir)
}

func (s *scenario) run(ctx context.Context, exe string, args []string) RunResult {
	if s.opts.Run != nil {
		return s.opts.Run(ctx, exe, args)
	}
	return runTool(ctx, exe, args, s.opts.Timeout)
}

// uploadManifest records a failed capture so the operator sees the tool
// output and exit code on the server even when no image was produced. A
// transport failure is returned so the collector retries the job.
func (s *scenario) uploadManifest(sink collector.Sink, job *protocol.Job, prof profile, path string, image *Image, probe Probe, started time.Time, run RunResult) error {
	manifest := s.manifest(job, prof, path, image, probe, started, run)
	return sink.Bytes(protocol.KindMemoryManifest, "memory_capture.json",
		"memory capture manifest: tool identity and failed capture result", Render(manifest))
}

func (s *scenario) manifest(job *protocol.Job, prof profile, path string, image *Image, probe Probe, started time.Time, run RunResult) Manifest {
	finished := s.opts.Now()
	m := Manifest{
		SchemaVersion:    1,
		Scenario:         protocol.ScenarioMemory,
		HostID:           job.HostID,
		JobID:            job.ID,
		StartedAt:        started.UTC(),
		FinishedAt:       finished.UTC(),
		DurationMS:       finished.Sub(started).Milliseconds(),
		Tool:             Tool{Name: prof.name, Version: s.opts.ToolVersion, Path: s.opts.ToolPath, SHA256: strings.ToLower(s.opts.ToolSHA256), Args: prof.args(path)},
		MemoryTotalBytes: probe.TotalMemory,
		DiskFreeBytes:    probe.FreeDisk,
		Image:            image,
		Result:           Result{Status: "completed", ExitCode: run.ExitCode, StdoutTail: run.Stdout, StderrTail: run.Stderr},
	}
	if run.Err != nil {
		m.Result.Status = "failed"
		m.Result.Error = run.Err.Error()
	}
	if image != nil {
		m.Notes = append(m.Notes,
			"raw physical memory; pagefile and hibernation file are not included",
			"captured on a live system: memory may change during acquisition",
		)
	}
	if run.Err == nil && run.ExitCode != 0 {
		m.Notes = append(m.Notes,
			fmt.Sprintf("%s reports a completed acquisition with exit code %d (0 is not used)", prof.name, run.ExitCode))
	}
	return m
}

// preflight rejects captures that cannot succeed before the tool runs.
func preflight(p Probe, maxBytes int64) error {
	if !p.Elevated {
		return errors.New("administrator privileges are required; run the agent as LocalSystem or an elevated account")
	}
	if p.TotalMemory <= 0 {
		return errors.New("could not determine the host's physical memory size")
	}
	if maxBytes < p.TotalMemory {
		return fmt.Errorf("configured -memory-max-bytes (%s) is smaller than physical memory (%s)", humanBytes(maxBytes), humanBytes(p.TotalMemory))
	}
	if need := p.TotalMemory + minFreeHeadroom; p.FreeDisk < need {
		return fmt.Errorf("not enough free space in -memory-out: need %s, have %s", humanBytes(need), humanBytes(p.FreeDisk))
	}
	return nil
}

// VerifyTool checks that the acquisition binary is a regular, non-symlinked
// file whose SHA-256 matches want. The agent calls it at startup and before
// every capture so a replaced binary is never executed.
func VerifyTool(path, want string) error {
	want = strings.ToLower(strings.TrimSpace(want))
	if len(want) != 64 {
		return errors.New("-memory-tool-sha256 must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(want); err != nil {
		return errors.New("-memory-tool-sha256 must be 64 hexadecimal characters")
	}
	f, err := collector.SecureOpen(path)
	if err != nil {
		return fmt.Errorf("open capture tool: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat capture tool: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("capture tool is not a regular file")
	}
	got, err := hashReader(f)
	if err != nil {
		return fmt.Errorf("hash capture tool: %w", err)
	}
	if got != want {
		return fmt.Errorf("capture tool digest mismatch: have %s, want %s", got, want)
	}
	return nil
}

func humanBytes(n int64) string {
	const (
		mib = 1 << 20
		gib = 1 << 30
	)
	switch {
	case n >= gib:
		if n%gib == 0 {
			return fmt.Sprintf("%d GiB", n/gib)
		}
		return fmt.Sprintf("%.1f GiB", float64(n)/gib)
	case n >= mib:
		return fmt.Sprintf("%d MiB", n/mib)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
