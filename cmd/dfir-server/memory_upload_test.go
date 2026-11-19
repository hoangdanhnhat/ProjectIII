package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"example.com/dfir-collector/internal/protocol"
)

// TestMemoryImageArtifactCap proves that memory_image is capped by the
// -max-memory-image value (so it can exceed the default 10 MiB), that every
// other kind keeps the default cap, and that a large artifact survives the
// upload/download round trip with its hash intact.
func TestMemoryImageArtifactCap(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	s.maxMemoryImage = 11 << 20
	ts := httptest.NewServer(s.routes())
	defer ts.Close()

	call := func(method, path, token string, body []byte, metadata string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Host-ID", "lab")
		if metadata != "" {
			req.Header.Set("X-Artifact-Metadata", metadata)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	closeStatus := func(r *http.Response, expected int) {
		t.Helper()
		defer r.Body.Close()
		if r.StatusCode != expected {
			b, _ := io.ReadAll(r.Body)
			t.Fatalf("HTTP %d, want %d: %s", r.StatusCode, expected, b)
		}
	}

	resp := call("POST", "/v1/jobs", "operator-secret", []byte(`{"host_id":"lab","scenario":"memory.v1"}`), "")
	if resp.StatusCode != 201 {
		t.Fatalf("create: %s", resp.Status)
	}
	var job protocol.Job
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	closeStatus(call("GET", "/v1/agent/jobs/next", "agent-secret", nil, ""), 200)

	artifact := func(kind protocol.Kind, data []byte) (protocol.Artifact, string) {
		hash := sha256.Sum256(data)
		id := sha256.Sum256([]byte(string(kind) + "\x00C:\\DFIR\\memory\\image.raw\x00" + hex.EncodeToString(hash[:])))
		a := protocol.Artifact{
			ID: hex.EncodeToString(id[:]), Kind: kind,
			Source: `C:\DFIR\memory\image.raw`, SHA256: hex.EncodeToString(hash[:]),
			Size: int64(len(data)), CollectedAt: time.Now().UTC(),
		}
		b, _ := json.Marshal(a)
		return a, string(b)
	}

	// Exactly the raised cap: accepted, even though it is above 10 MiB.
	image := bytes.Repeat([]byte("m"), 11<<20)
	a, metadata := artifact(protocol.KindMemoryImage, image)
	path := "/v1/agent/jobs/" + job.ID + "/artifacts/" + a.ID
	closeStatus(call("POST", path, "agent-secret", image, metadata), 201)
	// An idempotent retry of the same artifact is acknowledged.
	closeStatus(call("POST", path, "agent-secret", image, metadata), 200)
	// Download returns the same bytes, length and hash.
	resp = call("GET", "/v1/jobs/"+job.ID+"/artifacts/"+a.ID, "operator-secret", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("download: %s", resp.Status)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(got, image) {
		t.Fatalf("download body mismatch (%d bytes, %v)", len(got), err)
	}
	if resp.Header.Get("X-SHA256") != a.SHA256 || resp.ContentLength != int64(len(image)) {
		t.Fatalf("download headers: sha=%q length=%d", resp.Header.Get("X-SHA256"), resp.ContentLength)
	}

	// One byte above the memory cap: rejected before the body is stored.
	tooLarge, metadata := artifact(protocol.KindMemoryImage, bytes.Repeat([]byte("m"), 11<<20+1))
	closeStatus(call("POST", "/v1/agent/jobs/"+job.ID+"/artifacts/"+tooLarge.ID, "agent-secret", []byte("x"), metadata), 400)

	// Every other kind keeps the 10 MiB default.
	other := bytes.Repeat([]byte("u"), 10<<20+1)
	uo, metadata := artifact(protocol.KindUpload, other)
	closeStatus(call("POST", "/v1/agent/jobs/"+job.ID+"/artifacts/"+uo.ID, "agent-secret", other, metadata), 400)

	// Unknown kinds for the scenario are rejected.
	ho, metadata := artifact(protocol.KindHostRole, []byte("{}"))
	closeStatus(call("POST", "/v1/agent/jobs/"+job.ID+"/artifacts/"+ho.ID, "agent-secret", []byte("{}"), metadata), 400)

	// The manifest kind is accepted in the same job.
	manifest := []byte(`{"schema_version":1}`)
	mo, metadata := artifact(protocol.KindMemoryManifest, manifest)
	closeStatus(call("POST", "/v1/agent/jobs/"+job.ID+"/artifacts/"+mo.ID, "agent-secret", manifest, metadata), 201)
}
