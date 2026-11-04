package ti

import (
	"net/netip"
	"testing"
)

func TestParseEntryValue(t *testing.T) {
	for _, tc := range []struct {
		in, typ, want string
	}{
		{"8.8.8.8", EntryIP, "8.8.8.8"},
		{"  1.2.3.4 ", EntryIP, "1.2.3.4"},
		{"fe80::1", EntryIP, "fe80::1"},
		{"10.0.0.5/8", EntryCIDR, "10.0.0.0/8"},
		{"203.0.113.0/24", EntryCIDR, "203.0.113.0/24"},
		{"Example.COM.", EntryDomain, "example.com"},
		{"portal.internal", EntryDomain, "portal.internal"},
		{"localhost", EntryDomain, "localhost"},
		{"*.Microsoft.com", EntryWildcard, "*.microsoft.com"},
	} {
		typ, got, err := ParseEntryValue(tc.in)
		if err != nil {
			t.Fatalf("ParseEntryValue(%q): %v", tc.in, err)
		}
		if typ != tc.typ || got != tc.want {
			t.Errorf("ParseEntryValue(%q) = %s/%q, want %s/%q", tc.in, typ, got, tc.typ, tc.want)
		}
	}
	for _, bad := range []string{"", "   ", "*.", "*.a..b", "-bad.example", "bad-.example", "ex_ample.com", "not an ip", "10.0.0.0/99", "example.com/24"} {
		if _, _, err := ParseEntryValue(bad); err == nil {
			t.Errorf("ParseEntryValue(%q) accepted invalid value", bad)
		}
	}
}

func TestWhitelistAddRemoveList(t *testing.T) {
	ws, err := LoadWhitelist(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(ws.List()) == 0 {
		t.Fatal("default seed entries missing")
	}
	first, err := ws.Add("10.0.0.0/8", "internal network")
	if err != nil {
		t.Fatal(err)
	}
	// Same value again: idempotent, note updated, no duplicate.
	second, err := ws.Add("10.0.0.5/8", "updated note")
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.Value != "10.0.0.0/8" || second.Note != "updated note" {
		t.Fatalf("idempotent add changed the entry: %+v", second)
	}
	count := len(ws.List())
	if !ws.Remove(first.ID) {
		t.Fatal("Remove failed for existing ID")
	}
	if ws.Remove(first.ID) {
		t.Fatal("Remove succeeded twice for same ID")
	}
	if got := len(ws.List()); got != count-1 {
		t.Fatalf("list length after remove = %d, want %d", got, count-1)
	}
	if _, err := ws.Add("no spaces  allowed", ""); err == nil {
		t.Fatal("invalid value accepted")
	}
}

func TestWhitelistMatching(t *testing.T) {
	ws, err := LoadWhitelist(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1.2.3.4", "203.0.113.0/24", "portal.internal", "*.example.com"} {
		if _, err := ws.Add(v, ""); err != nil {
			t.Fatal(err)
		}
	}
	ip := func(s string) netip.Addr {
		t.Helper()
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		return addr
	}
	if _, ok := ws.MatchIP(ip("1.2.3.4")); !ok {
		t.Error("exact IP not matched")
	}
	if _, ok := ws.MatchIP(ip("203.0.113.77")); !ok {
		t.Error("CIDR member not matched")
	}
	if _, ok := ws.MatchIP(ip("203.0.114.1")); ok {
		t.Error("address outside CIDR matched")
	}
	if e, ok := ws.MatchIP(ip("1.2.3.4")); !ok || e.Value != "1.2.3.4" {
		t.Error("matched entry not returned")
	}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"portal.internal", true},
		{"Portal.Internal", true},
		{"example.com", true},          // wildcard covers the apex
		{"www.example.com", true},      // and subdomains
		{"deep.sub.example.com", true}, // at any depth
		{"notexample.com", false},      // suffix but not at a label boundary
		{"example.org", false},
		{"internal", false},
	} {
		if _, ok := ws.MatchDomain(tc.name); ok != tc.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", tc.name, ok, tc.want)
		}
	}
}

// TestWhitelistPersistsAndReloads verifies entries survive store reloads
// (the server restarts with the same data directory).
func TestWhitelistPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	ws, err := LoadWhitelist(dir)
	if err != nil {
		t.Fatal(err)
	}
	added, err := ws.Add("*.example.com", "trusted")
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadWhitelist(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.MatchDomain("www.example.com"); !ok {
		t.Fatal("entry lost across reload")
	}
	var found *Entry
	for _, e := range reloaded.List() {
		if e.ID == added.ID {
			found = &e
		}
	}
	if found == nil || found.Note != "trusted" {
		t.Fatalf("entry details lost across reload: %+v", found)
	}
}

// TestBlacklistStartsEmptyAndPersists pins the differences from the
// whitelist: no seed entries, and its own file.
func TestBlacklistStartsEmptyAndPersists(t *testing.T) {
	dir := t.TempDir()
	bl, err := LoadBlacklist(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(bl.List()); got != 0 {
		t.Fatalf("blacklist seeded with %d entries, want 0", got)
	}
	if bl.List() == nil {
		t.Fatal("empty blacklist List() returned nil; JSON would encode null instead of []")
	}
	if _, err := bl.Add("203.0.113.66", "known C2"); err != nil {
		t.Fatal(err)
	}
	if _, err := bl.Add("*.evil.example", "phishing"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadBlacklist(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.MatchDomain("mail.evil.example"); !ok {
		t.Fatal("wildcard blacklist entry lost across reload")
	}
	if e, ok := reloaded.MatchIP(mustAddr(t, "203.0.113.66")); !ok || e.Note != "known C2" {
		t.Fatalf("blacklist IP entry lost or note missing: %+v", e)
	}
	// The whitelist file must stay independent of the blacklist file.
	if _, err := LoadWhitelist(dir); err != nil {
		t.Fatal(err)
	}
	whitelist, err := LoadWhitelist(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := whitelist.MatchDomain("mail.evil.example"); ok {
		t.Fatal("blacklist entry leaked into the whitelist")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
