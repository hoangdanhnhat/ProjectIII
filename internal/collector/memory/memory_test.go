package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/collector/sinktest"
	"example.com/dfir-collector/internal/protocol"
)

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fakeTool writes a small executable-like file and returns its path and digest.
func fakeTool(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "winpmem_mini_x64_rc2.exe")
	data := []byte("not a real acquisition binary, used as a fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, sha(data)
}

func fixedNow() time.Time {
	return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
}

func baseOptions(t *testing.T, run func(ctx context.Context, exe string, args []string) RunResult) Options {
	t.Helper()
	tool, digest := fakeTool(t)
	return Options{
		ToolPath:    tool,
		ToolSHA256:  digest,
		ToolName:    "winpmem",
		ToolVersion: "4.0-rc2",
		OutDir:      t.TempDir(),
		MaxBytes:    4 << 20,
		Timeout:     time.Minute,
		Probe: func(string) (Probe, error) {
			return Probe{TotalMemory: 1 << 20, FreeDisk: 1 << 30, Elevated: true}, nil
		},
		Run: run,
		Now: fixedNow,
	}
}

func TestNeedsConfiguration(t *testing.T) {
	c := New(Options{}).(*scenario)
	err := c.Collect(context.Background(), &protocol.Job{ID: "j"}, &sinktest.Recorded{})
	if !errors.Is(err, collector.ErrNeedsConfig) {
		t.Fatalf("got %v, want ErrNeedsConfig", err)
	}
}

func TestVerifyTool(t *testing.T) {
	path, digest := fakeTool(t)
	if err := VerifyTool(path, strings.ToUpper(digest)); err != nil {
		t.Fatalf("matching digest: %v", err)
	}
	if err := VerifyTool(path, sha([]byte("other"))); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("mismatch: %v", err)
	}
	if err := VerifyTool(path, "short"); err == nil {
		t.Fatal("short digest accepted")
	}
	if err := VerifyTool(filepath.Join(t.TempDir(), "missing.exe"), digest); err == nil {
		t.Fatal("missing tool accepted")
	}
	if err := VerifyTool("relative/path.exe", digest); err == nil {
		t.Fatal("relative tool path accepted")
	}
}

func TestDigestMismatchIsConfigurationError(t *testing.T) {
	o := baseOptions(t, nil)
	o.ToolSHA256 = sha([]byte("wrong"))
	c := New(o).(*scenario)
	err := c.Collect(context.Background(), &protocol.Job{ID: "j"}, &sinktest.Recorded{})
	if !errors.Is(err, collector.ErrNeedsConfig) || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestProfileSelection(t *testing.T) {
	mini, err := lookupProfile("", `C:\tools\winpmem_mini_x64_rc2.exe`)
	if err != nil || mini.name != "winpmem-mini" || mini.ext != ".raw" {
		t.Fatalf("mini: %+v %v", mini, err)
	}
	if got := mini.args(`C:\out\img.raw`); len(got) != 1 || got[0] != `C:\out\img.raw` {
		t.Fatalf("mini args: %v", got)
	}
	if mini.okExit == nil || !mini.okExit(1) || mini.okExit(0) || mini.okExit(-1) {
		t.Fatalf("mini exit convention: 0=%v 1=%v -1=%v", mini.okExit != nil && mini.okExit(0), mini.okExit != nil && mini.okExit(1), mini.okExit != nil && mini.okExit(-1))
	}
	full, err := lookupProfile("", "/opt/winpmem/winpmem")
	if err != nil || full.name != "winpmem" {
		t.Fatalf("full: %+v %v", full, err)
	}
	if got := full.args("/out/img.raw"); len(got) != 1 || got[0] != "/out/img.raw" {
		t.Fatalf("full args: %v", got)
	}
	physical, err := lookupProfile("winpmem-physical", "/opt/winpmem/winpmem64.exe")
	if err != nil || physical.name != "winpmem-physical" {
		t.Fatalf("physical: %+v %v", physical, err)
	}
	if got := physical.args("/out/img.raw"); len(got) != 2 || got[0] != "-1" || got[1] != "/out/img.raw" {
		t.Fatalf("physical args: %v", got)
	}
	if _, err := lookupProfile("", "/opt/tool/dumpit.exe"); err == nil {
		t.Fatal("unknown tool accepted")
	}
	if _, err := lookupProfile("magnet", "/opt/tool/x.exe"); err == nil {
		t.Fatal("unsupported profile accepted")
	}
	explicit, err := lookupProfile("winpmem-mini", "/opt/tool/anything.exe")
	if err != nil || explicit.name != "winpmem-mini" {
		t.Fatalf("explicit: %+v %v", explicit, err)
	}
}

func TestCaptureNameIsSafeAndScoped(t *testing.T) {
	name := captureName(`..\evil*`, `job:1`, ".raw", fixedNow())
	if strings.ContainsAny(name, `/\:*?`) {
		t.Fatalf("unsafe name %q", name)
	}
	if !strings.HasPrefix(name, "memory-") || !strings.Contains(name, "job_1") {
		t.Fatalf("unexpected name %q", name)
	}
	if got := captureName("", "", ".raw", fixedNow()); !strings.Contains(got, "unknown") {
		t.Fatalf("empty components: %q", got)
	}
}

func TestFindCapturePicksNewest(t *testing.T) {
	dir := t.TempDir()
	older := filepath.Join(dir, captureName("h", "j", ".raw", fixedNow().Add(-time.Hour)))
	newer := filepath.Join(dir, captureName("h", "j", ".raw", fixedNow()))
	if err := os.WriteFile(older, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	// A symlink and an empty file must never be reused.
	if err := os.Symlink(newer, filepath.Join(dir, captureName("h", "j", ".raw", fixedNow().Add(time.Hour)))); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, captureName("h", "j", ".raw", fixedNow().Add(2*time.Hour))), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got, ok := findCapture(dir, "h", "j", ".raw")
	if !ok || got != newer {
		t.Fatalf("got %q, want %q", got, newer)
	}
	if _, ok := findCapture(dir, "h", "other", ".raw"); ok {
		t.Fatal("matched another job")
	}
}

func TestCollectSuccess(t *testing.T) {
	image := []byte("raw physical memory fixture")
	o := baseOptions(t, func(_ context.Context, _ string, args []string) RunResult {
		if len(args) != 1 {
			t.Fatalf("unexpected args: %v", args)
		}
		if err := os.WriteFile(args[0], image, 0600); err != nil {
			t.Fatal(err)
		}
		return RunResult{Stdout: "driver loaded\n", ExitCode: 1}
	})
	sink := &sinktest.Recorded{}
	job := &protocol.Job{ID: "job123", HostID: "lab-host", Scenario: protocol.ScenarioMemory}
	if err := New(o).Collect(context.Background(), job, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.Problems) != 0 {
		t.Fatalf("problems: %v", sink.Problems)
	}
	if len(sink.Files) != 1 || sink.Files[0].Kind != protocol.KindMemoryImage || !strings.Contains(sink.Files[0].Reason, "winpmem") {
		t.Fatalf("files: %+v", sink.Files)
	}
	if len(sink.BytesCalls) != 1 || sink.BytesCalls[0].Kind != protocol.KindMemoryManifest {
		t.Fatalf("manifests: %+v", sink.BytesCalls)
	}
	var m Manifest
	if err := json.Unmarshal(sink.BytesCalls[0].Data, &m); err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != 1 || m.Scenario != protocol.ScenarioMemory || m.HostID != "lab-host" || m.JobID != "job123" {
		t.Fatalf("manifest header: %+v", m)
	}
	if m.Image == nil || m.Image.Size != int64(len(image)) || m.Image.SHA256 != sha(image) {
		t.Fatalf("manifest image: %+v", m.Image)
	}
	if m.Tool.Name != "winpmem" || m.Tool.Version != "4.0-rc2" || m.Tool.SHA256 != o.ToolSHA256 {
		t.Fatalf("manifest tool: %+v", m.Tool)
	}
	if m.Result.Status != "completed" || m.Result.ExitCode != 1 || m.Result.StdoutTail != "driver loaded\n" {
		t.Fatalf("manifest result: %+v", m.Result)
	}
	if !strings.Contains(strings.Join(m.Notes, " "), "exit code 1") {
		t.Fatalf("manifest does not explain WinPmem's exit convention: %v", m.Notes)
	}
	if m.MemoryTotalBytes != 1<<20 || m.DiskFreeBytes != 1<<30 {
		t.Fatalf("manifest probe: %+v", m)
	}
	if len(m.Notes) == 0 {
		t.Fatal("manifest notes missing")
	}
	if _, err := os.Stat(sink.Files[0].Path); !os.IsNotExist(err) {
		t.Fatalf("local image not removed: %v", err)
	}

	// -memory-keep leaves the staged file behind.
	o = baseOptions(t, func(_ context.Context, _ string, args []string) RunResult {
		if err := os.WriteFile(args[0], image, 0600); err != nil {
			t.Fatal(err)
		}
		return RunResult{ExitCode: 1}
	})
	o.Keep = true
	sink = &sinktest.Recorded{}
	if err := New(o).Collect(context.Background(), job, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.Files) != 1 {
		t.Fatalf("keep: %+v", sink.Files)
	}
	if _, err := os.Stat(sink.Files[0].Path); err != nil {
		t.Fatalf("kept image missing: %v", err)
	}
}

func TestCollectToolFailureUploadsManifest(t *testing.T) {
	o := baseOptions(t, func(context.Context, string, []string) RunResult {
		return RunResult{Stdout: "starting", Stderr: "driver load failed", ExitCode: 5, Err: errors.New("exit code 5")}
	})
	sink := &sinktest.Recorded{}
	job := &protocol.Job{ID: "job123", HostID: "h"}
	if err := New(o).Collect(context.Background(), job, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.Files) != 0 {
		t.Fatalf("unexpected image upload: %+v", sink.Files)
	}
	if len(sink.Problems) != 1 || !strings.Contains(sink.Problems[0], "exit code 5") {
		t.Fatalf("problems: %v", sink.Problems)
	}
	if len(sink.BytesCalls) != 1 {
		t.Fatalf("manifests: %+v", sink.BytesCalls)
	}
	var m Manifest
	if err := json.Unmarshal(sink.BytesCalls[0].Data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Result.Status != "failed" || m.Result.ExitCode != 5 || m.Result.StderrTail != "driver load failed" || m.Result.Error == "" {
		t.Fatalf("failure manifest: %+v", m.Result)
	}
	if m.Image != nil {
		t.Fatalf("failure manifest has an image: %+v", m.Image)
	}
}

func TestCollectPreflightFailures(t *testing.T) {
	cases := []struct {
		name  string
		probe func(string) (Probe, error)
		max   int64
		want  string
	}{
		{"not elevated", func(string) (Probe, error) { return Probe{TotalMemory: 1 << 20, FreeDisk: 1 << 30}, nil }, 4 << 20, "administrator"},
		{"unknown memory", func(string) (Probe, error) { return Probe{FreeDisk: 1 << 30, Elevated: true}, nil }, 4 << 20, "physical memory"},
		{"image cap below memory", func(string) (Probe, error) {
			return Probe{TotalMemory: 20 << 20, FreeDisk: 21 << 20, Elevated: true}, nil
		}, 4 << 20, "smaller than physical memory"},
		{"low disk", func(string) (Probe, error) {
			return Probe{TotalMemory: 4 << 20, FreeDisk: 4<<20 + minFreeHeadroom - 1, Elevated: true}, nil
		}, 8 << 20, "free space"},
		{"probe error", func(string) (Probe, error) { return Probe{}, errors.New("token failure") }, 4 << 20, "token failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := baseOptions(t, func(context.Context, string, []string) RunResult {
				t.Fatal("tool must not run")
				return RunResult{}
			})
			o.Probe = tc.probe
			o.MaxBytes = tc.max
			sink := &sinktest.Recorded{}
			if err := New(o).Collect(context.Background(), &protocol.Job{ID: "j"}, sink); err != nil {
				t.Fatal(err)
			}
			if len(sink.Problems) != 1 || !strings.Contains(sink.Problems[0], tc.want) {
				t.Fatalf("problems: %v", sink.Problems)
			}
			if len(sink.BytesCalls) != 0 || len(sink.Files) != 0 {
				t.Fatalf("uploaded after preflight failure: %+v %+v", sink.BytesCalls, sink.Files)
			}
		})
	}
}

func TestPreflightDiskHeadroom(t *testing.T) {
	p := Probe{TotalMemory: 8 << 20, FreeDisk: 8<<20 + minFreeHeadroom - 1, Elevated: true}
	if err := preflight(p, 16<<20); err == nil || !strings.Contains(err.Error(), "free space") {
		t.Fatalf("got %v", err)
	}
	p.FreeDisk = 8<<20 + minFreeHeadroom
	if err := preflight(p, 16<<20); err != nil {
		t.Fatalf("got %v", err)
	}
}

func TestCollectReusesEarlierCapture(t *testing.T) {
	o := baseOptions(t, func(context.Context, string, []string) RunResult {
		t.Fatal("tool must not run when a capture exists")
		return RunResult{}
	})
	previous := []byte("capture from the first attempt")
	path := filepath.Join(o.OutDir, captureName("h", "j", ".raw", fixedNow().Add(-time.Minute)))
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	sink := &sinktest.Recorded{}
	if err := New(o).Collect(context.Background(), &protocol.Job{ID: "j", HostID: "h"}, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.Files) != 1 || sink.Files[0].Path != path {
		t.Fatalf("files: %+v", sink.Files)
	}
	if len(sink.Notes) != 1 || !strings.Contains(sink.Notes[0], "reusing capture") {
		t.Fatalf("notes: %v", sink.Notes)
	}
	var m Manifest
	if err := json.Unmarshal(sink.BytesCalls[0].Data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Image == nil || m.Image.SHA256 != sha(previous) {
		t.Fatalf("manifest image: %+v", m.Image)
	}
}

func TestInspectImageRejectsBadOutput(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.raw")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectImage(empty, 1<<20); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty: %v", err)
	}
	large := filepath.Join(dir, "large.raw")
	if err := os.WriteFile(large, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectImage(large, 4); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("large: %v", err)
	}
	if _, err := inspectImage(filepath.Join(dir, "missing.raw"), 1<<20); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestOversizedImageIsNotUploaded(t *testing.T) {
	o := baseOptions(t, func(_ context.Context, _ string, args []string) RunResult {
		if err := os.WriteFile(args[0], []byte("0123456789"), 0600); err != nil {
			t.Fatal(err)
		}
		return RunResult{ExitCode: 1}
	})
	o.MaxBytes = 4
	o.Probe = func(string) (Probe, error) {
		return Probe{TotalMemory: 2, FreeDisk: 1 << 30, Elevated: true}, nil
	}
	sink := &sinktest.Recorded{}
	if err := New(o).Collect(context.Background(), &protocol.Job{ID: "j"}, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.Files) != 0 {
		t.Fatalf("oversized image uploaded: %+v", sink.Files)
	}
	if len(sink.Problems) != 1 || !strings.Contains(sink.Problems[0], "above the 4 bytes limit") {
		t.Fatalf("problems: %v", sink.Problems)
	}
	if len(sink.BytesCalls) != 1 {
		t.Fatalf("failure manifest missing")
	}
}

func TestManifestRenderIsStableJSON(t *testing.T) {
	m := Manifest{SchemaVersion: 1, Scenario: protocol.ScenarioMemory, Notes: nil}
	data := Render(m)
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["notes"].([]any); !ok {
		t.Fatalf("notes is not an array: %s", data)
	}
	if m.Notes != nil {
		t.Fatal("Render modified its input")
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{limit: 4}
	if _, err := b.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("ghi")); err != nil {
		t.Fatal(err)
	}
	if b.String() != "abcd…(truncated)" {
		t.Fatalf("got %q", b.String())
	}
}

func TestRunToolTimeout(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses a POSIX shell fixture")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no shell")
	}
	res := runTool(context.Background(), sh, []string{"-c", "exec sleep 5"}, 50*time.Millisecond)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "timed out") {
		t.Fatalf("got %+v", res)
	}
}

// failingSink makes the manifest upload fail to prove the transport error is
// propagated so the job stays running for a retry.
type failingSink struct {
	*sinktest.Recorded
	err error
}

func (f *failingSink) Bytes(protocol.Kind, string, string, []byte) error { return f.err }

func TestManifestTransportErrorIsReturned(t *testing.T) {
	o := baseOptions(t, func(_ context.Context, _ string, args []string) RunResult {
		if err := os.WriteFile(args[0], []byte("image"), 0600); err != nil {
			t.Fatal(err)
		}
		return RunResult{ExitCode: 1}
	})
	boom := fmt.Errorf("connection reset")
	sink := &failingSink{Recorded: &sinktest.Recorded{}, err: boom}
	err := New(o).Collect(context.Background(), &protocol.Job{ID: "j"}, sink)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the transport error", err)
	}
}
