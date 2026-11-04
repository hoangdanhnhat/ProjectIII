package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"example.com/dfir-collector/internal/collector/netstat"
	"example.com/dfir-collector/internal/protocol"
)

// tiTestServer is a netstat.v1 job fixture: a snapshot with a public remote
// (with correlated domain), a private remote, and DNS cache entries.
func tiTestSnapshot() []byte {
	snap := &netstat.Snapshot{
		SchemaVersion: 2,
		GeneratedAt:   time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC),
		Connections: []netstat.Connection{
			{Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 51000, RemoteAddr: "93.184.216.34", RemotePort: 443, State: "ESTABLISHED", PID: 4020, Process: "chrome.exe", Domains: []string{"portal.example.com"}},
			{Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 51001, RemoteAddr: "10.0.0.9", RemotePort: 445, State: "ESTABLISHED", PID: 4, Process: "System"},
		},
		DNSCache: []netstat.DNSRecord{
			{Name: "portal.example.com", Type: "CNAME", Data: "cdn.example.net"},
			{Name: "cdn.example.net", Type: "A", Data: "93.184.216.34"},
			{Name: "intranet.corp", Type: "A", Data: "10.0.0.9"},
		},
	}
	return netstat.Render(snap)
}

type tiClient struct {
	t     *testing.T
	base  string
	token string
	host  string // optional X-Host-ID for agent-side calls
}

func (c tiClient) do(method, path string, body []byte) *http.Response {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if c.host != "" {
		req.Header.Set("X-Host-ID", c.host)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func (c tiClient) json(method, path string, body []byte, into any) *http.Response {
	c.t.Helper()
	resp := c.do(method, path, body)
	defer resp.Body.Close()
	if into != nil {
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
			c.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp
}

// runNetstatJob walks a netstat.v1 job through the agent API: create,
// claim, upload the snapshot, and report completion. The auto-enrichment
// worker starts when the result is accepted.
func runNetstatJob(t *testing.T, ts *httptest.Server, snapshot []byte) protocol.Job {
	t.Helper()
	op := tiClient{t: t, base: ts.URL, token: "operator-secret"}
	ag := tiClient{t: t, base: ts.URL, token: "agent-secret", host: "lab"}

	resp := op.json("POST", "/v1/jobs", []byte(`{"host_id":"lab","scenario":"netstat.v1"}`), nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: HTTP %d", resp.StatusCode)
	}
	resp = ag.do("GET", "/v1/agent/jobs/next", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll: HTTP %d", resp.StatusCode)
	}
	var jobs struct {
		Jobs []protocol.Job `json:"jobs"`
	}
	// The poll response was consumed above; fetch the running job via list.
	resp = op.json("GET", "/v1/jobs", nil, &jobs)
	resp.Body.Close()
	var job protocol.Job
	for _, j := range jobs.Jobs {
		if j.Scenario == "netstat.v1" && j.Status == "running" {
			job = j
		}
	}
	if job.ID == "" {
		t.Fatal("no running netstat job found")
	}

	hash := sha256.Sum256(snapshot)
	id := sha256.Sum256([]byte("netstat_snapshot\x00netstat_snapshot.json\x00" + hex.EncodeToString(hash[:])))
	artifact := protocol.Artifact{
		ID: hex.EncodeToString(id[:]), Kind: protocol.KindNetstatSnapshot,
		Source: "netstat_snapshot.json", SHA256: hex.EncodeToString(hash[:]),
		Size: int64(len(snapshot)), CollectedAt: time.Now().UTC(),
	}
	meta, _ := json.Marshal(artifact)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/agent/jobs/"+job.ID+"/artifacts/"+artifact.ID, bytes.NewReader(snapshot))
	req.Header.Set("Authorization", "Bearer agent-secret")
	req.Header.Set("X-Host-ID", "lab")
	req.Header.Set("X-Artifact-Metadata", string(meta))
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated && resp2.StatusCode != http.StatusOK {
		t.Fatalf("upload: HTTP %d", resp2.StatusCode)
	}

	resp = ag.json("POST", "/v1/agent/jobs/"+job.ID+"/result", []byte(`{"status":"completed"}`), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("result: HTTP %d", resp.StatusCode)
	}
	return job
}

// waitTI polls the job until enrichment leaves the running state.
func waitTI(t *testing.T, ts *httptest.Server, jobID string) protocol.Job {
	t.Helper()
	op := tiClient{t: t, base: ts.URL, token: "operator-secret"}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var job protocol.Job
		resp := op.json("GET", "/v1/jobs/"+jobID, nil, &job)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("get job: HTTP %d", resp.StatusCode)
		}
		if job.TIStatus != "" && job.TIStatus != "running" {
			return job
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("enrichment did not finish in time")
	return protocol.Job{}
}

// downloadTIReport fetches and decodes the job's ti_report artifact.
func downloadTIReport(t *testing.T, ts *httptest.Server, job protocol.Job) map[string]any {
	t.Helper()
	op := tiClient{t: t, base: ts.URL, token: "operator-secret"}
	var reportID string
	for _, a := range job.Artifacts {
		if a.Kind == protocol.KindTIReport {
			reportID = a.ID
		}
	}
	if reportID == "" {
		t.Fatalf("no ti_report artifact on job %s (status %s)", job.ID, job.TIStatus)
	}
	resp := op.do("GET", "/v1/jobs/"+job.ID+"/artifacts/"+reportID, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download ti_report: HTTP %d", resp.StatusCode)
	}
	var report map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	return report
}

func reportVerdict(t *testing.T, report map[string]any, typ, value string) string {
	t.Helper()
	indicators, _ := report["indicators"].([]any)
	for _, raw := range indicators {
		ind, _ := raw.(map[string]any)
		if ind["type"] == typ && ind["value"] == value {
			v, _ := ind["verdict"].(string)
			return v
		}
	}
	t.Fatalf("indicator %s %s missing from report", typ, value)
	return ""
}

// TestTISettingsEndpoints covers the operator settings API: masked key,
// updates, validation, and the whitelist payload.
func TestTISettingsEndpoints(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	op := tiClient{t: t, base: ts.URL, token: "operator-secret"}

	var initial struct {
		VT struct {
			Configured bool   `json:"configured"`
			KeyPreview string `json:"key_preview"`
			AutoEnrich bool   `json:"auto_enrich"`
			RatePerMin int    `json:"rate_per_min"`
			MaxQueries int    `json:"max_queries_per_job"`
		} `json:"vt"`
		Whitelist struct {
			Entries []map[string]any `json:"entries"`
		} `json:"whitelist"`
		Blacklist struct {
			Entries []map[string]any `json:"entries"`
		} `json:"blacklist"`
	}
	resp := op.json("GET", "/v1/settings/ti", nil, &initial)
	resp.Body.Close()
	if initial.VT.Configured || initial.VT.KeyPreview != "" {
		t.Fatalf("fresh install reports configured key: %+v", initial.VT)
	}
	if !initial.VT.AutoEnrich || initial.VT.RatePerMin != 4 || initial.VT.MaxQueries != 40 {
		t.Fatalf("defaults wrong: %+v", initial.VT)
	}
	if len(initial.Whitelist.Entries) == 0 {
		t.Fatal("seed whitelist entries missing")
	}
	if len(initial.Blacklist.Entries) != 0 {
		t.Fatalf("blacklist should start empty, got %d entries", len(initial.Blacklist.Entries))
	}

	// Settings require the operator token.
	resp = tiClient{t: t, base: ts.URL, token: "agent-secret"}.do("GET", "/v1/settings/ti", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("agent token accepted for settings: HTTP %d", resp.StatusCode)
	}

	// Invalid values are rejected.
	for _, bad := range []string{
		`{"vt_rate_per_min":0}`, `{"vt_rate_per_min":61}`,
		`{"vt_max_queries_per_job":0}`, `{"vt_max_queries_per_job":501}`,
		`{"vt_base_url":"ftp://nope"}`,
	} {
		resp = op.json("PUT", "/v1/settings/ti", []byte(bad), nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid settings %q accepted: HTTP %d", bad, resp.StatusCode)
		}
	}

	// A valid update round-trips; the key is masked.
	resp = op.json("PUT", "/v1/settings/ti", []byte(`{"vt_api_key":"abc123secretkey","vt_auto_enrich":false,"vt_rate_per_min":10,"vt_max_queries_per_job":25}`), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update: HTTP %d", resp.StatusCode)
	}
	var updated struct {
		VT struct {
			Configured bool   `json:"configured"`
			KeyPreview string `json:"key_preview"`
			AutoEnrich bool   `json:"auto_enrich"`
			RatePerMin int    `json:"rate_per_min"`
			MaxQueries int    `json:"max_queries_per_job"`
		} `json:"vt"`
	}
	resp = op.json("GET", "/v1/settings/ti", nil, &updated)
	resp.Body.Close()
	if !updated.VT.Configured || updated.VT.KeyPreview != "••••tkey" {
		t.Fatalf("masked preview wrong: %+v", updated.VT)
	}
	if updated.VT.AutoEnrich || updated.VT.RatePerMin != 10 || updated.VT.MaxQueries != 25 {
		t.Fatalf("update not applied: %+v", updated.VT)
	}

	// An empty key clears it.
	resp = op.json("PUT", "/v1/settings/ti", []byte(`{"vt_api_key":""}`), nil)
	resp.Body.Close()
	resp = op.json("GET", "/v1/settings/ti", nil, &updated)
	resp.Body.Close()
	if updated.VT.Configured {
		t.Fatal("empty key did not clear the configuration")
	}
}

// TestWhitelistEndpoints covers add/list/remove over HTTP.
func TestWhitelistEndpoints(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	op := tiClient{t: t, base: ts.URL, token: "operator-secret"}

	var entry map[string]any
	resp := op.json("POST", "/v1/whitelist", []byte(`{"value":"  Example.COM. ","note":"trusted vendor"}`), &entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: HTTP %d", resp.StatusCode)
	}
	if entry["value"] != "example.com" || entry["type"] != "domain" || entry["note"] != "trusted vendor" {
		t.Fatalf("entry not normalized: %+v", entry)
	}

	// Same value again updates the note and returns 200.
	resp = op.json("POST", "/v1/whitelist", []byte(`{"value":"example.com","note":"updated"}`), &entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || entry["note"] != "updated" {
		t.Fatalf("duplicate add: HTTP %d note=%v", resp.StatusCode, entry["note"])
	}

	// Wildcards and CIDRs are accepted; garbage is rejected.
	for _, ok := range []string{`{"value":"*.corp.example"}`, `{"value":"203.0.113.0/24"}`, `{"value":"1.2.3.4"}`} {
		resp = op.json("POST", "/v1/whitelist", []byte(ok), nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("valid value %s rejected: HTTP %d", ok, resp.StatusCode)
		}
	}
	for _, bad := range []string{`{"value":""}`, `{"value":"*.a b"}`, `{"value":"999.1.1.1"}`, `{"value":"x","note":"` + strings.Repeat("n", 201) + `"}`} {
		resp = op.json("POST", "/v1/whitelist", []byte(bad), nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid value %s accepted: HTTP %d", bad, resp.StatusCode)
		}
	}

	// Remove by ID through the settings listing.
	var settings struct {
		Whitelist struct {
			Entries []map[string]any `json:"entries"`
		} `json:"whitelist"`
	}
	resp = op.json("GET", "/v1/settings/ti", nil, &settings)
	resp.Body.Close()
	id, _ := settings.Whitelist.Entries[0]["id"].(string)
	if id == "" {
		t.Fatal("entries lack IDs")
	}
	resp = op.do("DELETE", "/v1/whitelist/"+id, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: HTTP %d", resp.StatusCode)
	}
	resp = op.do("DELETE", "/v1/whitelist/"+id, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete: HTTP %d", resp.StatusCode)
	}
}

// TestBlacklistEndpoints covers the deny-list API and that it stays
// independent from the allowlist.
func TestBlacklistEndpoints(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	op := tiClient{t: t, base: ts.URL, token: "operator-secret"}

	var entry map[string]any
	resp := op.json("POST", "/v1/blacklist", []byte(`{"value":"203.0.113.66","note":"known C2"}`), &entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: HTTP %d", resp.StatusCode)
	}
	if entry["value"] != "203.0.113.66" || entry["type"] != "ip" || entry["note"] != "known C2" {
		t.Fatalf("entry not stored correctly: %+v", entry)
	}

	// Duplicate updates the note and returns 200.
	resp = op.json("POST", "/v1/blacklist", []byte(`{"value":"203.0.113.66","note":"updated"}`), &entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || entry["note"] != "updated" {
		t.Fatalf("duplicate add: HTTP %d note=%v", resp.StatusCode, entry["note"])
	}

	// Wildcards work and invalid values are rejected.
	resp = op.json("POST", "/v1/blacklist", []byte(`{"value":"*.evil.example"}`), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("wildcard rejected: HTTP %d", resp.StatusCode)
	}
	for _, bad := range []string{`{"value":""}`, `{"value":"999.1.1.1"}`, `{"value":"x","note":"` + strings.Repeat("n", 201) + `"}`} {
		resp = op.json("POST", "/v1/blacklist", []byte(bad), nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid value %s accepted: HTTP %d", bad, resp.StatusCode)
		}
	}

	// The settings payload carries both lists, and entries do not leak
	// between them.
	var settings struct {
		Whitelist struct {
			Entries []map[string]any `json:"entries"`
		} `json:"whitelist"`
		Blacklist struct {
			Entries []map[string]any `json:"entries"`
		} `json:"blacklist"`
	}
	resp = op.json("GET", "/v1/settings/ti", nil, &settings)
	resp.Body.Close()
	if len(settings.Blacklist.Entries) != 2 {
		t.Fatalf("blacklist entries = %d, want 2", len(settings.Blacklist.Entries))
	}
	for _, w := range settings.Whitelist.Entries {
		if w["value"] == "203.0.113.66" || w["value"] == "*.evil.example" {
			t.Fatalf("blacklist entry leaked into the whitelist: %+v", w)
		}
	}

	id, _ := settings.Blacklist.Entries[0]["id"].(string)
	if id == "" {
		t.Fatal("blacklist entries lack IDs")
	}
	resp = op.do("DELETE", "/v1/blacklist/"+id, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: HTTP %d", resp.StatusCode)
	}
	resp = op.do("DELETE", "/v1/blacklist/"+id, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete: HTTP %d", resp.StatusCode)
	}
}

// TestTIAutoEnrichmentWithoutKey completes a netstat job without a
// VirusTotal key: the report is still produced with classification-only
// verdicts and the job records the skipped status.
func TestTIAutoEnrichmentWithoutKey(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()

	job := runNetstatJob(t, ts, tiTestSnapshot())
	finished := waitTI(t, ts, job.ID)
	if finished.TIStatus != "skipped" {
		t.Fatalf("ti status = %s (%s), want skipped", finished.TIStatus, finished.TIReason)
	}
	report := downloadTIReport(t, ts, finished)
	if got := reportVerdict(t, report, "ip", "93.184.216.34"); got != "skipped" {
		t.Fatalf("public IP verdict = %s, want skipped", got)
	}
	if got := reportVerdict(t, report, "ip", "10.0.0.9"); got != "private" {
		t.Fatalf("private IP verdict = %s, want private", got)
	}
	if got := reportVerdict(t, report, "domain", "intranet.corp"); got != "private" {
		t.Fatalf("internal domain verdict = %s, want private", got)
	}
	if _, ok := report["summary"].(map[string]any); !ok {
		t.Fatalf("report lacks summary: %v", report)
	}
}

// TestTIAutoEnrichmentWithVT runs the full pipeline against a fake
// VirusTotal: verdicts, re-run after whitelisting, and persistence of the
// report artifact on disk.
func TestTIAutoEnrichmentWithVT(t *testing.T) {
	var mu sync.Mutex
	requested := map[string]int{}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requested[r.URL.Path]++
		if r.Header.Get("x-apikey") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		stats := map[string]int{"harmless": 90}
		switch {
		case strings.HasSuffix(r.URL.Path, "/93.184.216.34"):
			stats = map[string]int{"malicious": 7, "harmless": 85}
		case strings.HasSuffix(r.URL.Path, "/portal.example.com"),
			strings.HasSuffix(r.URL.Path, "/cdn.example.net"):
			stats = map[string]int{"harmless": 80}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"attributes":{"reputation":-5,"as_owner":"Test AS","country":"US","last_analysis_stats":{"harmless":%d,"malicious":%d,"suspicious":0,"undetected":0,"timeout":0}}}}`, stats["harmless"], stats["malicious"])
	}))
	defer fake.Close()

	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.routes())
	defer ts.Close()
	op := tiClient{t: t, base: ts.URL, token: "operator-secret"}

	// rate 60/min = 1s between queries keeps the test fast while staying
	// inside the API's 1..60 validation window
	settings := fmt.Sprintf(`{"vt_api_key":"test-key","vt_base_url":%q,"vt_rate_per_min":60}`, fake.URL)
	resp := op.json("PUT", "/v1/settings/ti", []byte(settings), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings: HTTP %d", resp.StatusCode)
	}

	job := runNetstatJob(t, ts, tiTestSnapshot())
	finished := waitTI(t, ts, job.ID)
	if finished.TIStatus != "completed" {
		t.Fatalf("ti status = %s (%s), want completed", finished.TIStatus, finished.TIReason)
	}
	report := downloadTIReport(t, ts, finished)
	if got := reportVerdict(t, report, "ip", "93.184.216.34"); got != "malicious" {
		t.Fatalf("public IP verdict = %s, want malicious", got)
	}
	if got := reportVerdict(t, report, "domain", "cdn.example.net"); got != "clean" {
		t.Fatalf("domain verdict = %s, want clean", got)
	}
	mu.Lock()
	hits := requested["/api/v3/ip_addresses/93.184.216.34"]
	mu.Unlock()
	if hits != 1 {
		t.Fatalf("fake VT hits for the IP = %d, want 1", hits)
	}

	// Whitelisting the domain and re-running removes it from the query set
	// and flips its verdict.
	resp = op.json("POST", "/v1/whitelist", []byte(`{"value":"cdn.example.net","note":"ok"}`), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("whitelist: HTTP %d", resp.StatusCode)
	}
	resp = op.do("POST", "/v1/jobs/"+job.ID+"/ti", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("re-run: HTTP %d", resp.StatusCode)
	}
	again := waitTI(t, ts, job.ID)
	if again.TIStatus != "completed" {
		t.Fatalf("re-run status = %s (%s)", again.TIStatus, again.TIReason)
	}
	report2 := downloadTIReport(t, ts, again)
	if got := reportVerdict(t, report2, "domain", "cdn.example.net"); got != "whitelisted" {
		t.Fatalf("whitelisted domain verdict = %s, want whitelisted", got)
	}
	mu.Lock()
	hits2 := requested["/api/v3/domains/cdn.example.net"]
	mu.Unlock()
	if hits2 != 1 { // first run only; the re-run must skip it
		t.Fatalf("domain queried %d times after whitelisting, want 1", hits2)
	}

	// Blacklisting wins: the indicator is never queried again (it was
	// queried once in the first run) and its verdict flips.
	resp = op.json("POST", "/v1/blacklist", []byte(`{"value":"portal.example.com","note":"operator knowledge"}`), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("blacklist: HTTP %d", resp.StatusCode)
	}
	resp = op.do("POST", "/v1/jobs/"+job.ID+"/ti", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("blacklist re-run: HTTP %d", resp.StatusCode)
	}
	final := waitTI(t, ts, job.ID)
	if final.TIStatus != "completed" {
		t.Fatalf("blacklist re-run status = %s (%s)", final.TIStatus, final.TIReason)
	}
	report3 := downloadTIReport(t, ts, final)
	if got := reportVerdict(t, report3, "domain", "portal.example.com"); got != "blacklisted" {
		t.Fatalf("blacklisted domain verdict = %s, want blacklisted", got)
	}
	if summary, ok := report3["summary"].(map[string]any); ok {
		if n, _ := summary["blacklisted"].(float64); n != 1 {
			t.Fatalf("summary blacklisted = %v, want 1", summary["blacklisted"])
		}
	} else {
		t.Fatalf("report lacks summary: %v", report3)
	}
	mu.Lock()
	hits3 := requested["/api/v3/domains/portal.example.com"]
	mu.Unlock()
	if hits3 != 1 { // from the first run only; deny-listed values are skipped
		t.Fatalf("blacklisted domain queried %d times, want 1", hits3)
	}

	// The manifest references exactly one ti_report and the file verifies.
	s2, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	reloaded := s2.jobs[job.ID]
	count := 0
	for _, a := range reloaded.Artifacts {
		if a.Kind == protocol.KindTIReport {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("reloaded job references %d ti_reports, want 1", count)
	}

	// Guard rails: re-run refuses non-netstat jobs and unfinished jobs.
	resp = op.json("POST", "/v1/jobs", []byte(`{"host_id":"lab","scenario":"webshell.v1"}`), nil)
	resp.Body.Close()
	var listing struct {
		Jobs []protocol.Job `json:"jobs"`
	}
	resp = op.json("GET", "/v1/jobs", nil, &listing)
	resp.Body.Close()
	var other protocol.Job
	for _, j := range listing.Jobs {
		if j.Scenario == "webshell.v1" {
			other = j
			break
		}
	}
	if other.ID == "" {
		t.Fatal("webshell job not found")
	}
	resp = op.do("POST", "/v1/jobs/"+other.ID+"/ti", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("webshell re-run: HTTP %d, want 400", resp.StatusCode)
	}
	// An unfinished netstat job is rejected with 409.
	resp = op.json("POST", "/v1/jobs", []byte(`{"host_id":"lab","scenario":"netstat.v1"}`), nil)
	resp.Body.Close()
	resp = op.json("GET", "/v1/jobs", nil, &listing)
	resp.Body.Close()
	var queuedNetstat protocol.Job
	for _, j := range listing.Jobs {
		if j.Scenario == "netstat.v1" && j.Status == "queued" {
			queuedNetstat = j
			break
		}
	}
	if queuedNetstat.ID == "" {
		t.Fatal("queued netstat job not found")
	}
	resp = op.do("POST", "/v1/jobs/"+queuedNetstat.ID+"/ti", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("unfinished re-run: HTTP %d, want 409", resp.StatusCode)
	}
}

// TestTIInterruptedStatusIsFixedUp simulates a server restart during an
// enrichment run: the reload must surface "interrupted" instead of a
// permanently stuck "running".
func TestTIInterruptedStatusIsFixedUp(t *testing.T) {
	dir := t.TempDir()
	s, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	job := &protocol.Job{ID: "interruptedjob0000000000000000", HostID: "lab", Scenario: "netstat.v1", Status: "completed", CreatedAt: time.Now().UTC(), TIStatus: "running", Artifacts: []protocol.Artifact{}}
	if err := s.save(job); err != nil {
		t.Fatal(err)
	}
	s2, err := newServer(dir, "lab", "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	loaded := s2.jobs[job.ID]
	if loaded.TIStatus != "interrupted" || loaded.TIReason == "" {
		t.Fatalf("interrupted fixup failed: %q %q", loaded.TIStatus, loaded.TIReason)
	}
}
