//go:build linux || windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/collector/webshell"
	"example.com/dfir-collector/internal/protocol"
)

// stubCollector lets tests exercise runJob's outcome mapping without a real
// scenario.
type stubCollector struct {
	id        string
	platforms []string
	fn        func(job *protocol.Job, sink collector.Sink) error
}

func (s *stubCollector) ID() string          { return s.id }
func (s *stubCollector) Platforms() []string { return s.platforms }
func (s *stubCollector) Collect(ctx context.Context, job *protocol.Job, sink collector.Sink) error {
	return s.fn(job, sink)
}

func TestRunJobMapsOutcomes(t *testing.T) {
	newAgent := func(c collector.Collector) *Agent {
		return New(Options{
			ServerURL: "http://127.0.0.1:1", HostID: "h", Token: "t",
			Registry: collector.NewRegistry(c),
		})
	}
	cases := []struct {
		name   string
		c      collector.Collector
		status string
		reason string
	}{
		{
			name: "not applicable",
			c: &stubCollector{id: "s.v1", platforms: []string{"linux", "windows"}, fn: func(*protocol.Job, collector.Sink) error {
				return fmt.Errorf("%w: no web server config", collector.ErrNotApplicable)
			}},
			status: "skipped",
			reason: "no web server config",
		},
		{
			name: "needs configuration",
			c: &stubCollector{id: "s.v1", platforms: []string{"linux", "windows"}, fn: func(*protocol.Job, collector.Sink) error {
				return fmt.Errorf("%w: no uploads dir", collector.ErrNeedsConfig)
			}},
			status: "needs_configuration",
			reason: "no uploads dir",
		},
		{
			name:   "platform not implemented",
			c:      &stubCollector{id: "s.v1", platforms: []string{"windows"}, fn: func(*protocol.Job, collector.Sink) error { return nil }},
			status: "skipped",
			reason: "not implemented",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := newAgent(tc.c).runJob(context.Background(), protocol.Job{ID: "j", Scenario: "s.v1"})
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != tc.status || !strings.Contains(res.Reason, tc.reason) {
				t.Fatalf("got %+v, want status=%q reason~%q", res, tc.status, tc.reason)
			}
		})
	}
	// Unknown scenario: skipped, not an endless retry loop.
	res, err := newAgent(&stubCollector{id: "other.v1"}).runJob(context.Background(), protocol.Job{ID: "j", Scenario: "s.v1"})
	if err != nil || res.Status != "skipped" {
		t.Fatalf("unknown scenario: %+v %v", res, err)
	}
	// Transport error: returned so the job stays running for retry.
	boom := &stubCollector{id: "s.v1", platforms: []string{"linux", "windows"}, fn: func(*protocol.Job, collector.Sink) error {
		return errors.New("connection refused")
	}}
	if _, err := newAgent(boom).runJob(context.Background(), protocol.Job{ID: "j", Scenario: "s.v1"}); err == nil {
		t.Fatal("transport error must be returned")
	}
}

func TestSinkResultStatuses(t *testing.T) {
	s := newSink(&Agent{}, context.Background(), "job")
	if res := s.result(); res.Status != "completed" || res.Reason != "collected 0 artifacts, 0 errors" {
		t.Fatalf("empty: %+v", res)
	}
	s.count++
	s.Problem("one bad file")
	if res := s.result(); res.Status != "partial" {
		t.Fatalf("partial: %+v", res)
	}
	s2 := newSink(&Agent{}, context.Background(), "job")
	s2.Problem("a")
	s2.Problem("b")
	if res := s2.result(); res.Status != "failed" || res.Reason != "collected 0 artifacts, 2 errors; a; b" {
		t.Fatalf("failed: %+v", res)
	}
	// Notes never affect status but appear in the reason, capped at five
	// details overall.
	s3 := newSink(&Agent{}, context.Background(), "job")
	s3.count++
	s3.Note("dropped logs")
	for i := 0; i < 8; i++ {
		s3.Problem("p%d", i)
	}
	res := s3.result()
	if res.Status != "partial" {
		t.Fatalf("note must not fail the job: %+v", res)
	}
	if got := len(strings.Split(res.Reason, "; ")) - 1; got != 5 {
		t.Fatalf("problem cap: %d details in %q", got, res.Reason)
	}
}

type capturedArtifact struct {
	artifact protocol.Artifact
	body     string
}

// newUploadServer accepts artifact uploads and records them.
func newUploadServer(t *testing.T) (*httptest.Server, *[]capturedArtifact) {
	t.Helper()
	var got []capturedArtifact
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a protocol.Artifact
		if err := json.Unmarshal([]byte(r.Header.Get("X-Artifact-Metadata")), &a); err != nil {
			t.Errorf("metadata: %v", err)
		}
		body, _ := io.ReadAll(r.Body)
		got = append(got, capturedArtifact{artifact: a, body: string(body)})
		w.WriteHeader(201)
	}))
	t.Cleanup(ts.Close)
	return ts, &got
}

func newTestAgent(ts *httptest.Server, c collector.Collector) *Agent {
	return New(Options{
		ServerURL: ts.URL, HostID: "lab", Token: "test",
		Client: ts.Client(), Registry: collector.NewRegistry(c),
	})
}

func TestFileUploadFlow(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "fixture.php")
	if err := os.WriteFile(file, []byte("evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	ts, got := newUploadServer(t)
	a := newTestAgent(ts, &stubCollector{id: "s.v1", platforms: []string{"linux", "windows"}, fn: func(job *protocol.Job, sink collector.Sink) error {
		return sink.File(protocol.KindUpload, file, "script extension in upload directory")
	}})
	res, err := a.runJob(context.Background(), protocol.Job{ID: "j1", Scenario: "s.v1"})
	if err != nil || res.Status != "completed" || len(*got) != 1 {
		t.Fatalf("run: %+v %v, uploads=%d", res, err, len(*got))
	}
	cap := (*got)[0]
	if cap.body != "evidence" || cap.artifact.Source != file || cap.artifact.Kind != protocol.KindUpload ||
		cap.artifact.Size != int64(len("evidence")) || cap.artifact.Mode == "synthesized" {
		t.Fatalf("captured: %+v", cap)
	}

	// An unreadable path is a recorded failure, not an abort.
	(*got) = nil
	a = newTestAgent(ts, &stubCollector{id: "s.v1", platforms: []string{"linux", "windows"}, fn: func(job *protocol.Job, sink collector.Sink) error {
		if err := sink.File(protocol.KindUpload, filepath.Join(dir, "missing.php"), "r"); err != nil {
			return err
		}
		return sink.File(protocol.KindUpload, file, "r")
	}})
	res, err = a.runJob(context.Background(), protocol.Job{ID: "j2", Scenario: "s.v1"})
	if err != nil || res.Status != "partial" || len(*got) != 1 {
		t.Fatalf("partial: %+v %v, uploads=%d", res, err, len(*got))
	}
}

func TestBytesUploadFlow(t *testing.T) {
	ts, got := newUploadServer(t)
	a := newTestAgent(ts, &stubCollector{id: "s.v1", platforms: []string{"linux", "windows"}, fn: func(job *protocol.Job, sink collector.Sink) error {
		return sink.Bytes(protocol.Kind("netstat_snapshot"), "netstat.json", "connection table snapshot", []byte(`{"connections":[]}`))
	}})
	res, err := a.runJob(context.Background(), protocol.Job{ID: "j", Scenario: "s.v1"})
	if err != nil || res.Status != "completed" || len(*got) != 1 {
		t.Fatalf("run: %+v %v, uploads=%d", res, err, len(*got))
	}
	cap := (*got)[0]
	if cap.artifact.Mode != "synthesized" || cap.artifact.Source != "netstat.json" ||
		cap.artifact.Kind != protocol.Kind("netstat_snapshot") {
		t.Fatalf("captured: %+v", cap)
	}
}

// TestWebshellEndToEnd runs the real scenario through the real agent core,
// replacing the pre-refactor cmd/dfir-agent main_test.go.
func TestWebshellEndToEnd(t *testing.T) {
	dir := t.TempDir()
	uploads := filepath.Join(dir, "uploads")
	if err := os.Mkdir(uploads, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "apache2.conf")
	if err := os.WriteFile(config, []byte("# lab Apache config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploads, "example.PHP"), []byte("benign php fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploads, "photo.jpg"), []byte("normal image"), 0600); err != nil {
		t.Fatal(err)
	}
	ts, got := newUploadServer(t)
	opts := webshell.Options{UploadsDir: uploads, WebConfig: config, WebLogs: ""}
	a := newTestAgent(ts, webshell.New(opts))
	res, err := a.runJob(context.Background(), protocol.Job{ID: "fixture", Scenario: protocol.ScenarioWebshell})
	if err != nil || res.Status != "completed" || len(*got) != 1 {
		t.Fatalf("collect: %+v %v, uploads=%d", res, err, len(*got))
	}
	cap := (*got)[0]
	if cap.artifact.Kind != protocol.KindUpload || cap.artifact.Source != filepath.Join(uploads, "example.PHP") || cap.body != "benign php fixture" {
		t.Fatalf("unexpected artifact: %+v", cap)
	}

	// Missing web config: skipped, nothing uploaded.
	(*got) = nil
	opts.WebConfig = filepath.Join(dir, "not-apache.conf")
	a = newTestAgent(ts, webshell.New(opts))
	res, err = a.runJob(context.Background(), protocol.Job{ID: "other", Scenario: protocol.ScenarioWebshell})
	if err != nil || res.Status != "skipped" || len(*got) != 0 {
		t.Fatalf("role detection: %+v %v, uploads=%d", res, err, len(*got))
	}

	// Missing uploads dir: needs_configuration.
	opts.WebConfig = config
	opts.UploadsDir = filepath.Join(dir, "missing")
	a = newTestAgent(ts, webshell.New(opts))
	res, err = a.runJob(context.Background(), protocol.Job{ID: "missing", Scenario: protocol.ScenarioWebshell})
	if err != nil || res.Status != "needs_configuration" {
		t.Fatalf("missing uploads: %+v %v", res, err)
	}

	// Since: recently modified non-script files are collected too.
	(*got) = nil
	opts.UploadsDir = uploads
	since := time.Now().Add(-time.Hour)
	a = newTestAgent(ts, webshell.New(opts))
	res, err = a.runJob(context.Background(), protocol.Job{ID: "recent", Scenario: protocol.ScenarioWebshell, Since: &since})
	if err != nil || res.Status != "completed" || len(*got) != 2 {
		t.Fatalf("since: %+v %v, uploads=%d", res, err, len(*got))
	}
}
