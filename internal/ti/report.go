package ti

import (
	"encoding/json"
	"sort"
	"time"
)

// Verdict values for indicators.
const (
	VerdictBlacklisted = "blacklisted" // matched the operator deny list; never queried
	VerdictMalicious   = "malicious"   // 2+ engines flag it
	VerdictSuspicious  = "suspicious"  // exactly 1 engine flags it
	VerdictClean       = "clean"       // analyzed, no engine flags it
	VerdictUnrated     = "unrated"     // known to VT with no analyses, or query error
	VerdictWhitelisted = "whitelisted" // matched the operator allowlist
	VerdictPrivate     = "private"     // non-routable IP or internal hostname
	VerdictSkipped     = "skipped"     // query cap reached, VT disabled, or aborted
)

// TI run statuses stored on the job (protocol.Job.TIStatus).
const (
	StatusRunning     = "running"
	StatusCompleted   = "completed"
	StatusPartial     = "partial"     // some VirusTotal queries failed
	StatusSkipped     = "skipped"     // no VirusTotal key configured
	StatusFailed      = "failed"      // snapshot unreadable / internal error
	StatusInterrupted = "interrupted" // server restarted mid-run
)

// Indicator is one extracted public IP or domain with its verdict. For IPs
// the owning processes and correlated domains come from the snapshot, so
// the console can show "chrome.exe (4020) reached <domain> at <ip>".
type Indicator struct {
	Type           string   `json:"type"` // "ip" or "domain"
	Value          string   `json:"value"`
	Classification string   `json:"classification"`
	Verdict        string   `json:"verdict"`
	WhitelistMatch string   `json:"whitelist_match,omitempty"`
	BlacklistMatch string   `json:"blacklist_match,omitempty"`
	Domains        []string `json:"domains,omitempty"`
	Processes      []string `json:"processes,omitempty"`
	Connections    int      `json:"connections,omitempty"`
	VT             *VTInfo  `json:"vt,omitempty"`
}

// VTInfo is the VirusTotal evidence behind a verdict.
type VTInfo struct {
	Queried     bool      `json:"queried"`
	FromCache   bool      `json:"from_cache,omitempty"`
	Detections  string    `json:"detections,omitempty"` // "7/92"
	Reputation  int64     `json:"reputation,omitempty"`
	ASOwner     string    `json:"as_owner,omitempty"`
	Country     string    `json:"country,omitempty"`
	Link        string    `json:"link,omitempty"`
	RetrievedAt time.Time `json:"retrieved_at,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// Summary counts verdicts for the report banner.
type Summary struct {
	Total       int `json:"total"`
	Blacklisted int `json:"blacklisted"`
	Malicious   int `json:"malicious"`
	Suspicious  int `json:"suspicious"`
	Clean       int `json:"clean"`
	Unrated     int `json:"unrated"`
	Whitelisted int `json:"whitelisted"`
	Private     int `json:"private"`
	Skipped     int `json:"skipped"`
}

// Report is the ti_report artifact: everything the console needs to triage
// a netstat.v1 collection without re-reading the raw snapshot.
type Report struct {
	SchemaVersion  int         `json:"schema_version"`
	JobID          string      `json:"job_id"`
	HostID         string      `json:"host_id"`
	GeneratedAt    time.Time   `json:"generated_at"`
	SourceArtifact string      `json:"source_artifact"`
	SnapshotAt     time.Time   `json:"snapshot_generated_at"`
	VTEnabled      bool        `json:"vt_enabled"`
	VTQueried      int         `json:"vt_queried"`
	VTCacheHits    int         `json:"vt_cache_hits"`
	VTErrors       int         `json:"vt_errors"`
	MaxQueries     int         `json:"max_queries"`
	Summary        Summary     `json:"summary"`
	Indicators     []Indicator `json:"indicators"`
}

// VerdictFromStats applies the verdict thresholds to VirusTotal engine
// counts: 2+ malicious engines -> malicious; one malicious or any
// suspicious engine -> suspicious; analyzed and clean -> clean; no analyses
// -> unrated.
func VerdictFromStats(s Stats) string {
	switch {
	case s.Malicious >= 2:
		return VerdictMalicious
	case s.Malicious == 1 || s.Suspicious >= 1:
		return VerdictSuspicious
	case s.Total() > 0:
		return VerdictClean
	default:
		return VerdictUnrated
	}
}

// RenderReport serializes a report with deterministic indicator ordering:
// severity first (blacklisted, malicious, suspicious, unrated, skipped,
// clean, whitelisted, private), then type, then value.
func RenderReport(r *Report) []byte {
	if r.Indicators == nil {
		r.Indicators = []Indicator{}
	}
	rank := map[string]int{VerdictBlacklisted: 0, VerdictMalicious: 1, VerdictSuspicious: 2, VerdictUnrated: 3, VerdictSkipped: 4, VerdictClean: 5, VerdictWhitelisted: 6, VerdictPrivate: 7}
	sort.SliceStable(r.Indicators, func(i, j int) bool {
		a, b := r.Indicators[i], r.Indicators[j]
		if rank[a.Verdict] != rank[b.Verdict] {
			return rank[a.Verdict] < rank[b.Verdict]
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Value < b.Value
	})
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return []byte(`{"error":"render failed"}`)
	}
	return data
}
