package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.com/dfir-collector/internal/protocol"
)

func TestListJobsAndMeta(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()

	call := func(method, path, token string, body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	create := func() protocol.Job {
		t.Helper()
		resp := call("POST", "/v1/jobs", "operator-secret", []byte(`{"host_id":"lab","scenario":"webshell.v1"}`))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: HTTP %d", resp.StatusCode)
		}
		var job protocol.Job
		if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
			t.Fatal(err)
		}
		return job
	}

	first := create()
	time.Sleep(2 * time.Millisecond)
	second := create()

	resp := call("GET", "/v1/jobs", "operator-secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: HTTP %d", resp.StatusCode)
	}
	var listing struct {
		Jobs []protocol.Job `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(listing.Jobs) != 2 || listing.Jobs[0].ID != second.ID || listing.Jobs[1].ID != first.ID {
		t.Fatalf("jobs not newest-first: %+v", listing.Jobs)
	}

	resp = call("GET", "/v1/jobs", "agent-secret", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent token on list: HTTP %d, want 401", resp.StatusCode)
	}

	resp = call("GET", "/v1/meta", "operator-secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("meta: HTTP %d", resp.StatusCode)
	}
	var meta struct {
		HostID    string   `json:"host_id"`
		Scenarios []string `json:"scenarios"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if meta.HostID != "lab" || !equalScenarios(meta.Scenarios, protocol.ScenarioIDs()) {
		t.Fatalf("unexpected meta: %+v", meta)
	}

	resp = call("GET", "/v1/meta", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated meta: HTTP %d, want 401", resp.StatusCode)
	}
}

func TestJobLifecycleAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
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
	closeStatus(call("POST", "/v1/jobs", "agent-secret", []byte(`{"host_id":"lab","scenario":"webshell.v1"}`), ""), 401)
	r := call("POST", "/v1/jobs", "operator-secret", []byte(`{"host_id":"lab","scenario":"webshell.v1"}`), "")
	if r.StatusCode != 201 {
		t.Fatalf("create: %s", r.Status)
	}
	var job protocol.Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	r = call("GET", "/v1/agent/jobs/next", "agent-secret", nil, "")
	if r.StatusCode != 200 {
		t.Fatalf("poll: %s", r.Status)
	}
	r.Body.Close()
	data := []byte("sample fixture only")
	hash := sha256.Sum256(data)
	artifactID := sha256.Sum256([]byte("upload\x00/var/www/html/uploads/sample.php\x00" + hex.EncodeToString(hash[:])))
	a := protocol.Artifact{ID: hex.EncodeToString(artifactID[:]), Kind: "upload", Source: "/var/www/html/uploads/sample.php", SHA256: hex.EncodeToString(hash[:]), Size: int64(len(data)), CollectedAt: time.Now().UTC()}
	b, _ := json.Marshal(a)
	path := "/v1/agent/jobs/" + job.ID + "/artifacts/" + a.ID
	closeStatus(call("POST", path, "agent-secret", []byte("wrong"), string(b)), 400)
	closeStatus(call("POST", path, "agent-secret", data, string(b)), 201)
	closeStatus(call("POST", path, "agent-secret", data, string(b)), 200)
	closeStatus(call("POST", "/v1/agent/jobs/"+job.ID+"/result", "agent-secret", []byte(`{"status":"completed"}`), ""), 200)
	closeStatus(call("POST", path, "agent-secret", data, string(b)), 409)
	s2, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	loaded := s2.jobs[job.ID]
	if loaded.Status != "completed" || len(loaded.Artifacts) != 1 || loaded.Artifacts[0].SHA256 != a.SHA256 {
		t.Fatalf("job not persisted correctly: %+v", loaded)
	}
	stored, err := os.ReadFile(filepath.Join(dir, loaded.Artifacts[0].StoredAt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, data) {
		t.Fatal("stored evidence mismatch")
	}
	r = call("GET", "/v1/jobs/"+job.ID+"/artifacts/"+a.ID, "operator-secret", nil, "")
	if r.StatusCode != 200 {
		t.Fatalf("download: %s", r.Status)
	}
	got, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !bytes.Equal(got, data) || r.Header.Get("X-SHA256") != a.SHA256 {
		t.Fatal("download or hash mismatch")
	}
	if err := os.WriteFile(filepath.Join(dir, loaded.Artifacts[0].StoredAt), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	closeStatus(call("GET", "/v1/jobs/"+job.ID+"/artifacts/"+a.ID, "operator-secret", nil, ""), 500)
}

func equalScenarios(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestScenarioCatalogValidation(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
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

	// Unknown scenario: rejected at creation.
	closeStatus(call("POST", "/v1/jobs", "operator-secret", []byte(`{"host_id":"lab","scenario":"nope.v1"}`), ""), 400)
	// Catalog scenario: accepted.
	r := call("POST", "/v1/jobs", "operator-secret", []byte(`{"host_id":"lab","scenario":"webshell.v1"}`), "")
	var job protocol.Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if job.ID == "" {
		t.Fatal("job was not created")
	}
	// The job only becomes running when an agent claims it.
	closeStatus(call("GET", "/v1/agent/jobs/next", "agent-secret", nil, ""), 200)

	upload := func(kind protocol.Kind) {
		t.Helper()
		data := []byte("sample fixture only")
		hash := sha256.Sum256(data)
		id := sha256.Sum256([]byte(string(kind) + "\x00C:\\uploads\\sample\x00" + hex.EncodeToString(hash[:])))
		a := protocol.Artifact{ID: hex.EncodeToString(id[:]), Kind: kind, Source: `C:\uploads\sample`, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(data)), CollectedAt: time.Now().UTC()}
		b, _ := json.Marshal(a)
		closeStatus(call("POST", "/v1/agent/jobs/"+job.ID+"/artifacts/"+a.ID, "agent-secret", data, string(b)), 201)
	}
	// webshell.v1 accepts iis_log (and upload/apache_log) but not other kinds.
	upload(protocol.KindIISLog)

	data := []byte("sample fixture only")
	hash := sha256.Sum256(data)
	kind := protocol.Kind("netstat_snapshot")
	id := sha256.Sum256([]byte(string(kind) + "\x00C:\\uploads\\sample\x00" + hex.EncodeToString(hash[:])))
	a := protocol.Artifact{ID: hex.EncodeToString(id[:]), Kind: kind, Source: `C:\uploads\sample`, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(data)), CollectedAt: time.Now().UTC()}
	b, _ := json.Marshal(a)
	closeStatus(call("POST", "/v1/agent/jobs/"+job.ID+"/artifacts/"+a.ID, "agent-secret", data, string(b)), 400)
}
