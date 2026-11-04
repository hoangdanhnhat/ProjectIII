package ti

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"example.com/dfir-collector/internal/collector/netstat"
)

// Engine turns a netstat snapshot into a threat-intel report. The engine
// never mutates the snapshot; the raw artifact keeps its original hash.
type Engine struct {
	Store     *SettingsStore
	Whitelist *ListStore
	Blacklist *ListStore
	VT        *VTClient
}

// EnrichInput describes the job whose snapshot is being enriched.
type EnrichInput struct {
	Snapshot       *netstat.Snapshot
	JobID          string
	HostID         string
	SourceArtifact string
}

// Run extracts indicators, classifies them, and queries VirusTotal within
// the configured budget. Per-indicator problems never abort the run; the
// returned status and reason describe the overall outcome.
func (e *Engine) Run(ctx context.Context, in EnrichInput) (report *Report, status, reason string) {
	settings := e.Store.Get()
	report = &Report{
		SchemaVersion:  2,
		JobID:          in.JobID,
		HostID:         in.HostID,
		GeneratedAt:    time.Now().UTC(),
		SourceArtifact: in.SourceArtifact,
		SnapshotAt:     in.Snapshot.GeneratedAt,
		VTEnabled:      settings.VTAPIKey != "",
		MaxQueries:     settings.VTMaxQueries,
		Indicators:     []Indicator{},
	}

	ipIndicators := extractIPs(in.Snapshot, e.Whitelist, e.Blacklist)
	domainIndicators := extractDomains(in.Snapshot, e.Whitelist, e.Blacklist)
	candidates := append(ipIndicators, domainIndicators...)
	sortCandidates(candidates)

	budget := settings.VTMaxQueries
	var lastErr error
	if e.VT.Enabled() {
		aborted := false
		for i := range candidates {
			c := &candidates[i]
			if !needsQuery(c) {
				continue
			}
			if aborted || budget <= 0 {
				c.Verdict = VerdictSkipped
				continue
			}
			res, fromCache, err := e.VT.Lookup(ctx, c.Type, c.Value)
			if err != nil {
				report.VTErrors++
				lastErr = err
				if errors.Is(err, ErrInvalidKey) || errors.Is(err, errRateLimited) {
					// Every further query would fail the same way; stop
					// spending time on them and mark the rest skipped.
					aborted = true
					c.Verdict = VerdictSkipped
					c.VT = &VTInfo{Error: err.Error()}
					continue
				}
				c.Verdict = VerdictUnrated
				c.VT = &VTInfo{Error: err.Error()}
				continue
			}
			budget--
			if fromCache {
				report.VTCacheHits++
			} else {
				report.VTQueried++
			}
			c.Verdict = VerdictFromStats(res.Stats)
			c.VT = vtInfoFor(c, res, fromCache)
		}
	} else {
		for i := range candidates {
			if needsQuery(&candidates[i]) {
				candidates[i].Verdict = VerdictSkipped
			}
		}
	}

	report.Indicators = candidates
	report.Summary = summarize(report.Indicators)
	if !e.VT.Enabled() {
		status = StatusSkipped
		reason = "no VirusTotal API key configured; add one in Threat Intel settings and re-run"
	} else {
		status, reason = runOutcome(report, lastErr)
	}
	_ = e.VT.SaveCache()
	return report, status, reason
}

// needsQuery reports whether an indicator still needs a VirusTotal check.
// Private, whitelisted and blacklisted indicators are classified locally
// and never leave the server.
func needsQuery(c *Indicator) bool {
	switch c.Verdict {
	case VerdictPrivate, VerdictWhitelisted, VerdictBlacklisted:
		return false
	}
	return true
}

// runOutcome picks the final run status: partial when queries failed,
// completed otherwise (a hit query cap is documented in the reason, not an
// error).
func runOutcome(r *Report, lastErr error) (string, string) {
	if r.VTErrors > 0 && lastErr != nil {
		return StatusPartial, fmt.Sprintf("%d VirusTotal %s failed: %s", r.VTErrors, plural(r.VTErrors, "query", "queries"), lastErr)
	}
	if skipped := r.Summary.Skipped; skipped > 0 {
		return StatusCompleted, fmt.Sprintf("%d of %d indicators skipped: VirusTotal query cap (%d) reached", skipped, r.Summary.Total, r.MaxQueries)
	}
	return StatusCompleted, ""
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// extractIPs builds one indicator per distinct remote address, merging the
// owning processes, correlated domains, and connection count. Private,
// blacklisted and whitelisted addresses are classified without a query;
// the blacklist wins when a value appears in both lists.
func extractIPs(snap *netstat.Snapshot, wl, bl *ListStore) []Indicator {
	type agg struct {
		processes   map[string]bool
		domains     map[string]bool
		conns       int
		established bool
	}
	byAddr := map[netip.Addr]*agg{}
	var order []netip.Addr
	for i := range snap.Connections {
		c := &snap.Connections[i]
		if c.RemoteAddr == "" {
			continue
		}
		addr, err := netip.ParseAddr(c.RemoteAddr)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() {
			continue // LISTEN rows with 0.0.0.0/:: remotes
		}
		a := byAddr[addr]
		if a == nil {
			a = &agg{processes: map[string]bool{}, domains: map[string]bool{}}
			byAddr[addr] = a
			order = append(order, addr)
		}
		a.conns++
		a.processes[processLabel(c)] = true
		if c.State == "ESTABLISHED" {
			a.established = true
		}
		for _, d := range c.Domains {
			if d != "" {
				a.domains[strings.ToLower(d)] = true
			}
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i].String() < order[j].String() })

	out := make([]Indicator, 0, len(order))
	for _, addr := range order {
		a := byAddr[addr]
		ind := Indicator{
			Type:        "ip",
			Value:       addr.String(),
			Domains:     sortedSet(a.domains),
			Processes:   sortedSet(a.processes),
			Connections: a.conns,
		}
		if class := IPClass(addr); class == ClassPrivate {
			ind.Classification = ClassPrivate
			ind.Verdict = VerdictPrivate
		} else if entry, ok := matchEntryIP(bl, addr); ok {
			// The deny list wins over the allowlist: an operator-asserted
			// "known bad" is triage-critical and is never queried. A
			// conflicting allowlist match is recorded so the console can
			// surface the conflict.
			ind.Classification = ClassBlacklisted
			ind.Verdict = VerdictBlacklisted
			ind.BlacklistMatch = entry.Value
			if wlEntry, ok := matchEntryIP(wl, addr); ok {
				ind.WhitelistMatch = wlEntry.Value
			}
		} else if entry, ok := matchEntryIP(wl, addr); ok {
			ind.Classification = ClassWhitelisted
			ind.Verdict = VerdictWhitelisted
			ind.WhitelistMatch = entry.Value
		} else {
			ind.Classification = ClassPublic
			ind.Verdict = VerdictUnrated // pending query
			if a.established {
				ind.Connections = -a.conns // priority marker, restored below
			}
		}
		out = append(out, ind)
	}
	return out
}

// extractDomains builds one indicator per distinct cached DNS name.
// Single-label names and names resolving only to private addresses are
// internal hostnames and never queried; blacklist matches are known bad and
// never queried either (blacklist wins over whitelist on conflict).
func extractDomains(snap *netstat.Snapshot, wl, bl *ListStore) []Indicator {
	if len(snap.DNSCache) == 0 {
		return nil
	}
	resolved := netstat.ResolvedAddrs(snap.DNSCache)
	names := make([]string, 0, len(resolved))
	for name := range resolved {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Indicator, 0, len(names))
	for _, name := range names {
		ind := Indicator{Type: "domain", Value: name}
		// Internal hostnames are never queried: single-label names (no
		// dot) and names whose every resolvable address is private. A
		// name with no resolvable addresses stays an external candidate
		// — its address records may simply have been evicted.
		internal := !strings.Contains(name, ".")
		if !internal {
			hasAny, hasPublic := false, false
			for _, addr := range resolved[name] {
				hasAny = true
				if IPClass(addr) == ClassPublic {
					hasPublic = true
					break
				}
			}
			internal = hasAny && !hasPublic
		}
		switch {
		case internal:
			ind.Classification = ClassInternal
			ind.Verdict = VerdictPrivate
		default:
			if entry, ok := matchEntryDomain(bl, name); ok {
				ind.Classification = ClassBlacklisted
				ind.Verdict = VerdictBlacklisted
				ind.BlacklistMatch = entry.Value
				if wlEntry, ok := matchEntryDomain(wl, name); ok {
					ind.WhitelistMatch = wlEntry.Value
				}
			} else if entry, ok := matchEntryDomain(wl, name); ok {
				ind.Classification = ClassWhitelisted
				ind.Verdict = VerdictWhitelisted
				ind.WhitelistMatch = entry.Value
			} else {
				ind.Classification = ClassPublic
				ind.Verdict = VerdictUnrated // pending query
			}
		}
		out = append(out, ind)
	}
	return out
}

// matchEntryIP/matchEntryDomain tolerate a nil list so callers that only
// use one list keep working.
func matchEntryIP(ls *ListStore, addr netip.Addr) (Entry, bool) {
	if ls == nil {
		return Entry{}, false
	}
	return ls.MatchIP(addr)
}

func matchEntryDomain(ls *ListStore, name string) (Entry, bool) {
	if ls == nil {
		return Entry{}, false
	}
	return ls.MatchDomain(name)
}

// sortCandidates orders the query queue by triage value: established
// remote IPs with correlated domains first (clear user activity), then
// other established IPs, then any IPs, then domains; ties break
// alphabetically for determinism.
func sortCandidates(candidates []Indicator) {
	rank := func(c Indicator) int {
		established := c.Type == "ip" && c.Connections < 0 // priority marker
		switch {
		case established && len(c.Domains) > 0:
			return 0
		case established:
			return 1
		case c.Type == "ip":
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		ri, rj := rank(candidates[i]), rank(candidates[j])
		if ri != rj {
			return ri < rj
		}
		if candidates[i].Value != candidates[j].Value {
			return candidates[i].Value < candidates[j].Value
		}
		return candidates[i].Type < candidates[j].Type
	})
	for i := range candidates {
		if candidates[i].Connections < 0 {
			candidates[i].Connections = -candidates[i].Connections // restore count
		}
	}
}

func vtInfoFor(c *Indicator, res VTResult, fromCache bool) *VTInfo {
	info := &VTInfo{
		Queried:     true,
		FromCache:   fromCache,
		Detections:  res.Stats.Detections(),
		Reputation:  res.Reputation,
		ASOwner:     res.ASOwner,
		Country:     res.Country,
		RetrievedAt: res.RetrievedAt,
		Link:        vtLink(c.Type, c.Value),
	}
	return info
}

func vtLink(kind, value string) string {
	if kind == "ip" {
		return "https://www.virustotal.com/gui/ip-address/" + value
	}
	return "https://www.virustotal.com/gui/domain/" + value
}

func summarize(indicators []Indicator) Summary {
	s := Summary{Total: len(indicators)}
	for _, ind := range indicators {
		switch ind.Verdict {
		case VerdictBlacklisted:
			s.Blacklisted++
		case VerdictMalicious:
			s.Malicious++
		case VerdictSuspicious:
			s.Suspicious++
		case VerdictClean:
			s.Clean++
		case VerdictUnrated:
			s.Unrated++
		case VerdictWhitelisted:
			s.Whitelisted++
		case VerdictPrivate:
			s.Private++
		case VerdictSkipped:
			s.Skipped++
		}
	}
	return s
}

func processLabel(c *netstat.Connection) string {
	if c.Process != "" {
		return fmt.Sprintf("%s (%d)", c.Process, c.PID)
	}
	return fmt.Sprintf("pid %d", c.PID)
}

func sortedSet(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
