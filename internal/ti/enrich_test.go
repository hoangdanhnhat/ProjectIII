package ti

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"example.com/dfir-collector/internal/collector/netstat"
)

// fakeVT is a configurable VirusTotal v3 double that counts requests.
type fakeVT struct {
	mu      sync.Mutex
	hits    int
	ips     map[string]Stats
	domains map[string]Stats
	als     map[string]int // permanent status overrides, e.g. 429
}

func newFakeVT() *fakeVT {
	return &fakeVT{ips: map[string]Stats{}, domains: map[string]Stats{}, als: map[string]int{}}
}

func (f *fakeVT) hitsCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

func (f *fakeVT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if r.Header.Get("x-apikey") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/v3/ip_addresses/") {
		ip := strings.TrimPrefix(path, "/api/v3/ip_addresses/")
		if code, ok := f.als["ip:"+ip]; ok {
			w.WriteHeader(code)
			return
		}
		writeVTResponse(w, f.ips[ip])
		return
	}
	if strings.HasPrefix(path, "/api/v3/domains/") {
		dom := strings.TrimPrefix(path, "/api/v3/domains/")
		if code, ok := f.als["domain:"+dom]; ok {
			w.WriteHeader(code)
			return
		}
		writeVTResponse(w, f.domains[dom])
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func writeVTResponse(w http.ResponseWriter, s Stats) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"id": "test",
			"attributes": map[string]any{
				"reputation": 0,
				"as_owner":   "Test AS",
				"country":    "US",
				"last_analysis_stats": map[string]int{
					"harmless":   s.Harmless,
					"malicious":  s.Malicious,
					"suspicious": s.Suspicious,
					"undetected": s.Undetected,
					"timeout":    s.Timeout,
				},
			},
		},
	})
}

// testEnv wires an engine against a fake VirusTotal server.
type testEnv struct {
	engine    *Engine
	settings  *SettingsStore
	whitelist *ListStore
	blacklist *ListStore
	vt        *VTClient
	fake      *fakeVT
	server    *httptest.Server
}

func newTestEnv(t *testing.T, key string) *testEnv {
	t.Helper()
	dir := t.TempDir()
	fake := newFakeVT()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	settings, err := LoadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Update(func(s *Settings) {
		s.VTAPIKey = key
		s.VTBaseURL = server.URL
		s.VTRatePerMin = 6000 // effectively unthrottled
		s.VTMaxQueries = 40
	}); err != nil {
		t.Fatal(err)
	}
	whitelist, err := LoadWhitelist(dir)
	if err != nil {
		t.Fatal(err)
	}
	blacklist, err := LoadBlacklist(dir)
	if err != nil {
		t.Fatal(err)
	}
	vt := NewVTClient(settings, LoadCache(dir))
	return &testEnv{
		engine:    &Engine{Store: settings, Whitelist: whitelist, Blacklist: blacklist, VT: vt},
		settings:  settings,
		whitelist: whitelist,
		blacklist: blacklist,
		vt:        vt,
		fake:      fake,
		server:    server,
	}
}

func testSnapshot() *netstat.Snapshot {
	return &netstat.Snapshot{
		SchemaVersion: 2,
		GeneratedAt:   time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC),
		Connections: []netstat.Connection{
			{Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 51000, RemoteAddr: "93.184.216.34", RemotePort: 443, State: "ESTABLISHED", PID: 4020, Process: "chrome.exe", Domains: []string{"portal.example.com"}},
			{Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 51001, RemoteAddr: "1.2.3.4", RemotePort: 80, State: "ESTABLISHED", PID: 4020, Process: "chrome.exe"},
			{Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 51002, RemoteAddr: "5.6.7.8", RemotePort: 25, State: "ESTABLISHED", PID: 300, Process: "mailer.exe"},
			{Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 51003, RemoteAddr: "8.8.8.8", RemotePort: 53, State: "ESTABLISHED", PID: 100, Process: "svchost.exe"},
			{Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 51004, RemoteAddr: "10.0.0.9", RemotePort: 445, State: "ESTABLISHED", PID: 4, Process: "System"},
			{Proto: "tcp", LocalAddr: "0.0.0.0", LocalPort: 80, RemoteAddr: "0.0.0.0", RemotePort: 0, State: "LISTEN", PID: 4, Process: "System"},
			{Proto: "udp", LocalAddr: "0.0.0.0", LocalPort: 138, PID: 908, Process: "nbtsvc.exe"},
		},
		DNSCache: []netstat.DNSRecord{
			{Name: "portal.example.com", Type: "CNAME", Data: "cdn.example.net"},
			{Name: "cdn.example.net", Type: "A", Data: "93.184.216.34"},
			{Name: "bad.example", Type: "A", Data: "1.2.3.4"},
			{Name: "update.microsoft.com", Type: "A", Data: "8.8.8.8"},
			{Name: "intranet.corp", Type: "A", Data: "10.0.0.9"},
			{Name: "wpad", Type: "A", Data: "10.0.0.9"},
		},
	}
}

func findIndicator(t *testing.T, r *Report, typ, value string) *Indicator {
	t.Helper()
	for i := range r.Indicators {
		if r.Indicators[i].Type == typ && r.Indicators[i].Value == value {
			return &r.Indicators[i]
		}
	}
	t.Fatalf("indicator %s %q not found in report", typ, value)
	return nil
}

// TestRunWithoutKeyClassifiesOnly verifies the no-key path: indicators are
// still extracted and classified, queries are skipped, status is skipped.
func TestRunWithoutKeyClassifiesOnly(t *testing.T) {
	env := newTestEnv(t, "")
	report, status, _ := env.engine.Run(context.Background(), EnrichInput{
		Snapshot: testSnapshot(), JobID: "j1", HostID: "win-lab", SourceArtifact: "a1",
	})
	if status != StatusSkipped {
		t.Fatalf("status = %s, want skipped", status)
	}
	if ip := findIndicator(t, report, "ip", "93.184.216.34"); ip.Verdict != VerdictSkipped || ip.Classification != ClassPublic {
		t.Errorf("public IP verdict = %s/%s, want skipped/public", ip.Verdict, ip.Classification)
	}
	if ip := findIndicator(t, report, "ip", "10.0.0.9"); ip.Verdict != VerdictPrivate {
		t.Errorf("private IP verdict = %s, want private", ip.Verdict)
	}
	if dom := findIndicator(t, report, "domain", "update.microsoft.com"); dom.Verdict != VerdictWhitelisted {
		t.Errorf("whitelisted domain verdict = %s, want whitelisted", dom.Verdict)
	}
	if dom := findIndicator(t, report, "domain", "wpad"); dom.Verdict != VerdictPrivate {
		t.Errorf("single-label name verdict = %s, want private", dom.Verdict)
	}
	if dom := findIndicator(t, report, "domain", "intranet.corp"); dom.Verdict != VerdictPrivate {
		t.Errorf("internal-resolving domain verdict = %s, want private", dom.Verdict)
	}
	if env.fake.hitsCount() != 0 {
		t.Fatalf("fake VT received %d requests without a key", env.fake.hitsCount())
	}
}

// TestRunQueriesAndVerdicts covers the full happy path: verdict mapping,
// process/domain enrichment on IP indicators, whitelist and private skips,
// and summary counts.
func TestRunQueriesAndVerdicts(t *testing.T) {
	env := newTestEnv(t, "test-key")
	env.fake.ips["93.184.216.34"] = Stats{Malicious: 7, Harmless: 85} // malicious
	env.fake.ips["1.2.3.4"] = Stats{Malicious: 1, Undetected: 91}     // suspicious
	env.fake.ips["5.6.7.8"] = Stats{}                                 // 404 -> unrated
	env.fake.ips["8.8.8.8"] = Stats{Harmless: 90}                     // clean
	env.fake.domains["bad.example"] = Stats{Malicious: 3}             // malicious
	env.fake.domains["cdn.example.net"] = Stats{Harmless: 80}         // clean
	env.fake.domains["portal.example.com"] = Stats{Harmless: 80}      // clean

	report, status, reason := env.engine.Run(context.Background(), EnrichInput{
		Snapshot: testSnapshot(), JobID: "j2", HostID: "win-lab", SourceArtifact: "a2",
	})
	if status != StatusCompleted || reason != "" {
		t.Fatalf("status = %s (%s), want completed", status, reason)
	}
	check := func(typ, value, verdict string) {
		t.Helper()
		if ind := findIndicator(t, report, typ, value); ind.Verdict != verdict {
			t.Errorf("%s %s verdict = %s, want %s", typ, value, ind.Verdict, verdict)
		}
	}
	check("ip", "93.184.216.34", VerdictMalicious)
	check("ip", "1.2.3.4", VerdictSuspicious)
	check("ip", "5.6.7.8", VerdictUnrated)
	check("ip", "8.8.8.8", VerdictClean)
	check("ip", "10.0.0.9", VerdictPrivate)
	check("domain", "bad.example", VerdictMalicious)
	check("domain", "cdn.example.net", VerdictClean)
	check("domain", "update.microsoft.com", VerdictWhitelisted)

	ip := findIndicator(t, report, "ip", "93.184.216.34")
	if got := strings.Join(ip.Processes, ";"); got != "chrome.exe (4020)" {
		t.Errorf("processes = %q", got)
	}
	if got := strings.Join(ip.Domains, ";"); got != "portal.example.com" {
		t.Errorf("domains = %q", got)
	}
	if ip.Connections != 1 || ip.VT == nil || ip.VT.Detections != "7/92" || ip.VT.ASOwner != "Test AS" {
		t.Errorf("IP indicator details wrong: %+v vt=%+v", ip, ip.VT)
	}
	if report.Summary.Malicious != 2 || report.Summary.Suspicious != 1 || report.Summary.Clean != 3 {
		t.Errorf("summary = %+v", report.Summary)
	}
	// 4 public IPs + 3 public domains (microsoft whitelisted, corp/wpad internal)
	if got := env.fake.hitsCount(); got != 7 {
		t.Fatalf("fake VT hits = %d, want 7", got)
	}
	if report.VTQueried != 7 {
		t.Fatalf("report VTQueried = %d, want 7", report.VTQueried)
	}
}

// TestRunHonorsBlacklist verifies deny-list semantics: matched IPs and
// domains get verdict "blacklisted" without ever reaching VirusTotal, the
// deny list wins over a conflicting allowlist entry (recording both
// matches), and the summary counts it separately.
func TestRunHonorsBlacklist(t *testing.T) {
	env := newTestEnv(t, "test-key")
	for _, v := range []string{"93.184.216.34", "*.example.net"} {
		if _, err := env.blacklist.Add(v, "operator knowledge"); err != nil {
			t.Fatal(err)
		}
	}
	// Conflict: the value sits in both lists; the blacklist must win.
	if _, err := env.whitelist.Add("portal.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := env.blacklist.Add("portal.example.com", ""); err != nil {
		t.Fatal(err)
	}

	report, status, reason := env.engine.Run(context.Background(), EnrichInput{
		Snapshot: testSnapshot(), JobID: "jb", HostID: "win-lab", SourceArtifact: "ab",
	})
	if status != StatusCompleted || reason != "" {
		t.Fatalf("status = %s (%s), want completed", status, reason)
	}
	ip := findIndicator(t, report, "ip", "93.184.216.34")
	if ip.Verdict != VerdictBlacklisted || ip.BlacklistMatch != "93.184.216.34" || ip.Classification != ClassBlacklisted {
		t.Fatalf("blacklisted IP = %+v", ip)
	}
	if ip.VT != nil {
		t.Fatalf("blacklisted IP carries VT info, it must not be queried: %+v", ip.VT)
	}
	if dom := findIndicator(t, report, "domain", "cdn.example.net"); dom.Verdict != VerdictBlacklisted || dom.BlacklistMatch != "*.example.net" {
		t.Fatalf("wildcard blacklist domain = %+v", dom)
	}
	conflict := findIndicator(t, report, "domain", "portal.example.com")
	if conflict.Verdict != VerdictBlacklisted || conflict.WhitelistMatch != "portal.example.com" || conflict.BlacklistMatch != "portal.example.com" {
		t.Fatalf("conflict handling wrong (blacklist must win, both matches recorded): %+v", conflict)
	}
	if report.Summary.Blacklisted != 3 {
		t.Fatalf("summary blacklisted = %d, want 3", report.Summary.Blacklisted)
	}
	// Only 1.2.3.4, 5.6.7.8, 8.8.8.8 and bad.example remain queryable.
	if got := env.fake.hitsCount(); got != 4 {
		t.Fatalf("fake VT hits = %d, want 4 (blacklisted indicators must be skipped)", got)
	}
	if report.VTQueried != 4 {
		t.Fatalf("report VTQueried = %d, want 4", report.VTQueried)
	}
}

// TestRunUsesCache runs the engine twice; the second run must serve every
// verdict from the cache without new requests.
func TestRunUsesCache(t *testing.T) {
	env := newTestEnv(t, "test-key")
	env.fake.ips["93.184.216.34"] = Stats{Malicious: 5}
	run := func() *Report {
		report, status, _ := env.engine.Run(context.Background(), EnrichInput{
			Snapshot: testSnapshot(), JobID: "j3", HostID: "win-lab", SourceArtifact: "a3",
		})
		if status != StatusCompleted {
			t.Fatalf("status = %s", status)
		}
		return report
	}
	run()
	first := env.fake.hitsCount()
	report := run()
	if got := env.fake.hitsCount(); got != first {
		t.Fatalf("second run made %d new requests, want 0", got-first)
	}
	if report.VTCacheHits != report.VTQueried+report.VTCacheHits {
		t.Fatalf("cache hits not counted: %+v", report)
	}
	if report.VTQueried != 0 {
		t.Fatalf("second run VTQueried = %d, want 0", report.VTQueried)
	}
	if ip := findIndicator(t, report, "ip", "93.184.216.34"); ip.Verdict != VerdictMalicious {
		t.Fatalf("cached verdict = %s, want malicious", ip.Verdict)
	}
}

// TestRunQueryCapPrioritizesEstablished verifies the budget: with a cap of
// one query the established remote wins and the rest are skipped with a
// completed status that documents the cap.
func TestRunQueryCapPrioritizesEstablished(t *testing.T) {
	env := newTestEnv(t, "test-key")
	env.fake.ips["93.184.216.34"] = Stats{Malicious: 9}
	if err := env.settings.Update(func(s *Settings) { s.VTMaxQueries = 1 }); err != nil {
		t.Fatal(err)
	}
	report, status, reason := env.engine.Run(context.Background(), EnrichInput{
		Snapshot: testSnapshot(), JobID: "j4", HostID: "win-lab", SourceArtifact: "a4",
	})
	if status != StatusCompleted {
		t.Fatalf("status = %s (%s), want completed", status, reason)
	}
	if !strings.Contains(reason, "query cap") {
		t.Fatalf("reason %q does not mention the cap", reason)
	}
	if got := env.fake.hitsCount(); got != 1 {
		t.Fatalf("fake VT hits = %d, want 1", got)
	}
	if ip := findIndicator(t, report, "ip", "93.184.216.34"); ip.Verdict != VerdictMalicious {
		t.Fatalf("priority query picked %s", ip.Value)
	}
	if ip := findIndicator(t, report, "ip", "8.8.8.8"); ip.Verdict != VerdictSkipped {
		t.Fatalf("over-cap verdict = %s, want skipped", ip.Verdict)
	}
}

// TestRunRateLimitedAbortsPartial verifies a 429 aborts the loop, marks the
// rest skipped, and finishes the run as partial.
func TestRunRateLimitedAbortsPartial(t *testing.T) {
	env := newTestEnv(t, "test-key")
	env.fake.als["ip:93.184.216.34"] = http.StatusTooManyRequests
	report, status, reason := env.engine.Run(context.Background(), EnrichInput{
		Snapshot: testSnapshot(), JobID: "j5", HostID: "win-lab", SourceArtifact: "a5",
	})
	if status != StatusPartial {
		t.Fatalf("status = %s (%s), want partial", status, reason)
	}
	if report.VTErrors == 0 {
		t.Fatalf("errors not counted")
	}
	skipped := 0
	for _, ind := range report.Indicators {
		if ind.Verdict == VerdictSkipped {
			skipped++
		}
	}
	if skipped == 0 {
		t.Fatalf("no indicators skipped after abort")
	}
	if report.Summary.Skipped != skipped {
		t.Fatalf("summary skips = %d, want %d", report.Summary.Skipped, skipped)
	}
}

// TestVerdictFromStats pins the verdict thresholds.
func TestVerdictFromStats(t *testing.T) {
	for _, tc := range []struct {
		stats Stats
		want  string
	}{
		{Stats{Malicious: 2, Harmless: 90}, VerdictMalicious},
		{Stats{Malicious: 1}, VerdictSuspicious},
		{Stats{Suspicious: 1, Harmless: 90}, VerdictSuspicious},
		{Stats{Harmless: 92}, VerdictClean},
		{Stats{Undetected: 92}, VerdictClean},
		{Stats{}, VerdictUnrated},
		{Stats{Timeout: 92}, VerdictClean},
	} {
		if got := VerdictFromStats(tc.stats); got != tc.want {
			t.Errorf("VerdictFromStats(%+v) = %s, want %s", tc.stats, got, tc.want)
		}
	}
}

// TestRenderReportSortsBySeverity keeps the artifact deterministic and
// triage-ordered.
func TestRenderReportSortsBySeverity(t *testing.T) {
	r := &Report{
		SchemaVersion: 1,
		JobID:         "j6",
		Indicators: []Indicator{
			{Type: "ip", Value: "9.9.9.9", Verdict: VerdictClean},
			{Type: "domain", Value: "bad.example", Verdict: VerdictMalicious},
			{Type: "ip", Value: "1.2.3.4", Verdict: VerdictPrivate},
			{Type: "ip", Value: "5.5.5.5", Verdict: VerdictMalicious},
		},
	}
	data := string(RenderReport(r))
	badIdx := strings.Index(data, `"bad.example"`)
	ipIdx := strings.Index(data, `"5.5.5.5"`)
	cleanIdx := strings.Index(data, `"9.9.9.9"`)
	privateIdx := strings.Index(data, `"1.2.3.4"`)
	if !(badIdx < ipIdx && ipIdx < cleanIdx && cleanIdx < privateIdx) {
		t.Fatalf("indicators not severity-ordered in render:\n%s", data)
	}
	if r.Indicators[0].Type != "domain" || r.Indicators[0].Value != "bad.example" {
		t.Fatalf("first indicator = %+v, want bad.example", r.Indicators[0])
	}
	if !strings.Contains(data, `"indicators": [`) {
		t.Fatalf("render not indented JSON:\n%.200s", data)
	}
	_ = fmt.Sprint()
}
