//go:build linux || windows

package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

func TestUploadTimeoutScalesWithSize(t *testing.T) {
	if got := uploadTimeout(0); got != uploadFloorTimeout {
		t.Fatalf("empty: %v", got)
	}
	if got := uploadTimeout(int64(uploadMinRate)); got != uploadFloorTimeout+time.Second {
		t.Fatalf("one second of data: %v", got)
	}
	if got := uploadTimeout(1 << 40); got != uploadMaxTimeout {
		t.Fatalf("huge: %v", got)
	}
}

func TestAgentClientBudgets(t *testing.T) {
	a := New(Options{ServerURL: "http://127.0.0.1:1", HostID: "h", Token: "t"})
	if a.client.Timeout != 60*time.Second {
		t.Fatalf("polling client timeout: %v", a.client.Timeout)
	}
	if a.uploadClient.Timeout != 0 {
		t.Fatalf("upload client must rely on per-request deadlines, got %v", a.uploadClient.Timeout)
	}
	if a.memoryImageLimit != DefaultMemoryImageLimit {
		t.Fatalf("memory limit: %d", a.memoryImageLimit)
	}
}

// TestMemoryImageLimitIsKindSpecific proves that files above the default
// 10 MiB cap are refused for ordinary kinds but accepted for memory_image,
// and that the body is streamed with a Content-Length rather than buffered.
func TestMemoryImageLimitIsKindSpecific(t *testing.T) {
	var bodies int
	var meta protocol.Artifact
	var contentLength int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.Unmarshal([]byte(r.Header.Get("X-Artifact-Metadata")), &meta); err != nil {
			t.Errorf("metadata: %v", err)
		}
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("body: %v", err)
		}
		contentLength = r.ContentLength
		if r.ContentLength != n {
			t.Errorf("content length %d, body %d", r.ContentLength, n)
		}
		bodies++
		w.WriteHeader(201)
	}))
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	big := filepath.Join(dir, "large.bin")
	data := make([]byte, maxArtifact+1)
	if err := os.WriteFile(big, data, 0600); err != nil {
		t.Fatal(err)
	}
	collectorFor := func(kind protocol.Kind) *stubCollector {
		return &stubCollector{id: "s.v1", platforms: []string{"linux", "windows"}, fn: func(_ *protocol.Job, sink collector.Sink) error {
			return sink.File(kind, big, "test artifact")
		}}
	}

	a := newTestAgent(ts, collectorFor(protocol.KindUpload))
	res, err := a.runJob(context.Background(), protocol.Job{ID: "j1", Scenario: "s.v1"})
	if err != nil || res.Status != "failed" || bodies != 0 {
		t.Fatalf("upload kind: %+v %v, bodies=%d", res, err, bodies)
	}

	a = newTestAgent(ts, collectorFor(protocol.KindMemoryImage))
	res, err = a.runJob(context.Background(), protocol.Job{ID: "j2", Scenario: "s.v1"})
	if err != nil || res.Status != "completed" || bodies != 1 {
		t.Fatalf("memory kind: %+v %v, bodies=%d", res, err, bodies)
	}
	if contentLength != int64(len(data)) || meta.Kind != protocol.KindMemoryImage {
		t.Fatalf("content length %d kind %q", contentLength, meta.Kind)
	}
}

// TestRejectedArtifactDoesNotLoopForever proves that a 400/413 response is a
// recorded problem, not a transport error that keeps the job running.
func TestRejectedArtifactDoesNotLoopForever(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		http.Error(w, "invalid artifact metadata", http.StatusBadRequest)
	}))
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	file := filepath.Join(dir, "dump.raw")
	if err := os.WriteFile(file, []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	a := newTestAgent(ts, &stubCollector{id: "s.v1", platforms: []string{"linux", "windows"}, fn: func(_ *protocol.Job, sink collector.Sink) error {
		return sink.File(protocol.KindMemoryImage, file, "test artifact")
	}})
	res, err := a.runJob(context.Background(), protocol.Job{ID: "j", Scenario: "s.v1"})
	if err != nil {
		t.Fatalf("a rejected artifact must not be returned as a transport error: %v", err)
	}
	if res.Status != "failed" || !strings.Contains(res.Reason, "HTTP 400") {
		t.Fatalf("result: %+v", res)
	}
}
