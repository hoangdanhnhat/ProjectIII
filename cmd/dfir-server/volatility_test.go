package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.com/dfir-collector/internal/protocol"
	"example.com/dfir-collector/internal/volatility"
)

func fakeVolWrapper(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vol-wrapper")
	script := `#!/bin/sh
img=""
out=""
mods=""
while [ $# -gt 0 ]; do
  case "$1" in
    -i) img="$2"; shift 2 ;;
    -o) out="$2"; shift 2 ;;
    -m) mods="$2"; shift 2 ;;
    *) shift ;;
  esac
done
base=$(basename "$img")
while IFS= read -r p; do
  [ -z "$p" ] && continue
  printf '{"plugin":"%s"}\n' "$p" > "$out/${base}_${p}.jsonl"
  printf '    Module %s completed in 1.00 seconds\n' "$p"
done < "$mods"
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

// newVolatilityTestServer returns a server with one completed memory job.
func newVolatilityTestServer(t *testing.T, wrapper string) (*server, *protocol.Job) {
	t.Helper()
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator", "agent")
	if err != nil {
		t.Fatal(err)
	}
	imageData := []byte("fake memory image")
	hash := sha256.Sum256(imageData)
	image := protocol.Artifact{
		ID:          strings.Repeat("a", 64),
		Kind:        protocol.KindMemoryImage,
		Source:      `C:\DFIR\memory\image.raw`,
		Reason:      "fixture",
		SHA256:      hex.EncodeToString(hash[:]),
		Size:        int64(len(imageData)),
		Mode:        "-rw-------",
		CollectedAt: time.Now().UTC(),
		StoredAt:    "artifacts/job1/" + strings.Repeat("a", 64),
	}
	job := &protocol.Job{
		ID: "job1", HostID: "lab", Scenario: protocol.ScenarioMemory,
		Status: "completed", CreatedAt: time.Now().UTC(),
		Artifacts: []protocol.Artifact{image},
	}
	if err := os.MkdirAll(filepath.Join(dir, "artifacts", job.ID), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, image.StoredAt), imageData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.save(job); err != nil {
		t.Fatal(err)
	}
	s.jobs[job.ID] = job
	s.volRunner = volatility.New(volatility.Config{
		VolPath:     "/bin/true",
		WrapperPath: wrapper,
		WorkRoot:    filepath.Join(dir, "analysis"),
		Plugins:     []string{"windows.info.Info", "windows.pslist.PsList"},
		Timeout:     10 * time.Second,
		MaxOutput:   1 << 20,
	})
	s.volAuto = true
	return s, job
}

func waitForVolatility(t *testing.T, s *server, job *protocol.Job) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		status := job.VolatilityStatus
		reason := job.VolatilityReason
		s.mu.Unlock()
		if status != volatility.StatusRunning {
			if status == "" {
				t.Fatalf("analysis never started: %q", reason)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("analysis did not finish; status=%s", status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestVolatilityAutoAnalysis(t *testing.T) {
	s, job := newVolatilityTestServer(t, fakeVolWrapper(t))

	s.mu.Lock()
	started := s.volatilityTriggerLocked(job, false)
	s.mu.Unlock()
	if !started {
		t.Fatal("auto analysis did not start")
	}
	waitForVolatility(t, s, job)

	s.mu.Lock()
	status, reason := job.VolatilityStatus, job.VolatilityReason
	artifacts := append([]protocol.Artifact(nil), job.Artifacts...)
	s.mu.Unlock()
	if status != volatility.StatusCompleted || !strings.Contains(reason, "2/2 plugins") {
		t.Fatalf("status=%s reason=%q", status, reason)
	}

	var reportArtifact protocol.Artifact
	plugins := 0
	for _, artifact := range artifacts {
		switch artifact.Kind {
		case protocol.KindVolatilityPlugin:
			plugins++
			if artifact.Size == 0 || artifact.StoredAt == "" {
				t.Fatalf("plugin artifact: %+v", artifact)
			}
		case protocol.KindVolatilityReport:
			reportArtifact = artifact
		}
	}
	if plugins != 2 || reportArtifact.ID == "" {
		t.Fatalf("artifacts: %+v", artifacts)
	}
	data, err := os.ReadFile(filepath.Join(s.dir, reportArtifact.StoredAt))
	if err != nil {
		t.Fatal(err)
	}
	var report volatility.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Summary.Completed != 2 || report.Summary.Rows != 2 || report.Engine.Version != volatility.DefaultEngineVersion {
		t.Fatalf("report: %+v", report)
	}
	if report.Plugins[0].ArtifactID == "" {
		t.Fatalf("plugin artifact id missing: %+v", report.Plugins[0])
	}

	// A second automatic trigger for the same image is a no-op.
	s.mu.Lock()
	if s.volatilityTriggerLocked(job, false) {
		t.Fatal("auto trigger repeated for the same image")
	}
	// A manual re-run is allowed and replaces the analysis artifacts.
	if !s.volatilityTriggerLocked(job, true) {
		t.Fatal("manual re-run was refused")
	}
	s.mu.Unlock()
	waitForVolatility(t, s, job)
	s.mu.Lock()
	count := 0
	for _, artifact := range job.Artifacts {
		if artifact.Kind == protocol.KindVolatilityPlugin || artifact.Kind == protocol.KindVolatilityReport {
			count++
		}
	}
	s.mu.Unlock()
	if count != 3 {
		t.Fatalf("re-run left %d analysis artifacts, want 3", count)
	}
}

func TestVolatilityRequiresConfiguration(t *testing.T) {
	s, job := newVolatilityTestServer(t, fakeVolWrapper(t))
	s.volRunner = nil
	s.mu.Lock()
	started := s.volatilityTriggerLocked(job, true)
	s.mu.Unlock()
	if started || job.VolatilityStatus != "" {
		t.Fatalf("analysis started without a runner")
	}
}

func TestVolatilityInterruptedOnRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator", "agent")
	if err != nil {
		t.Fatal(err)
	}
	job := &protocol.Job{
		ID: "job-restart", HostID: "lab", Scenario: protocol.ScenarioMemory,
		Status: "completed", VolatilityStatus: volatility.StatusRunning,
		CreatedAt: time.Now().UTC(), Artifacts: []protocol.Artifact{},
	}
	if err := s.save(job); err != nil {
		t.Fatal(err)
	}
	s.jobs[job.ID] = job
	reloaded, err := newServer(dir, "lab", "operator", "agent")
	if err != nil {
		t.Fatal(err)
	}
	got := reloaded.jobs[job.ID]
	if got == nil || got.VolatilityStatus != volatility.StatusInterrupted || !strings.Contains(got.VolatilityReason, "restart") {
		t.Fatalf("job: %+v", got)
	}
}

func TestVolatilityOutcome(t *testing.T) {
	completed := &volatility.Report{Summary: volatility.Summary{Requested: 2, Completed: 2, Rows: 7}}
	if status, reason := volatilityOutcome(completed, nil); status != volatility.StatusCompleted || !strings.Contains(reason, "2/2") {
		t.Fatalf("completed: %s %q", status, reason)
	}
	partial := &volatility.Report{
		Summary: volatility.Summary{Requested: 2, Completed: 1, Failed: 1, Rows: 3},
		Plugins: []volatility.PluginResult{
			{Name: "windows.pslist.PsList", Status: volatility.StatusCompleted},
			{Name: "windows.netscan.NetScan", Status: volatility.StatusFailed},
		},
	}
	if status, reason := volatilityOutcome(partial, nil); status != volatility.StatusPartial || !strings.Contains(reason, "NetScan") {
		t.Fatalf("partial: %s %q", status, reason)
	}
	none := &volatility.Report{Summary: volatility.Summary{Requested: 2, Failed: 2}}
	if status, reason := volatilityOutcome(none, nil); status != volatility.StatusFailed || !strings.Contains(reason, "kernel") {
		t.Fatalf("failed: %s %q", status, reason)
	}
}
