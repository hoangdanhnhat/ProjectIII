package ti

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Whitelist entry types.
const (
	EntryIP       = "ip"
	EntryCIDR     = "cidr"
	EntryDomain   = "domain"
	EntryWildcard = "domain_wildcard"
)

const whitelistFile = "whitelist.json"

// Entry is one operator-managed allowlist rule. Whitelisted indicators are
// recorded in reports (verdict "whitelisted") but never sent to VirusTotal.
type Entry struct {
	ID        string    `json:"id"`
	Value     string    `json:"value"` // normalized form
	Type      string    `json:"type"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ParseEntryValue classifies and normalizes a whitelist value: an IP
// address, a CIDR network (host bits masked), a domain, or a single leading
// wildcard domain (*.example.com covers example.com and subdomains).
func ParseEntryValue(v string) (typ, normalized string, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", "", errors.New("empty value")
	}
	if rest, ok := strings.CutPrefix(v, "*."); ok {
		dom, err := normalizeDomain(rest)
		if err != nil {
			return "", "", err
		}
		return EntryWildcard, "*." + dom, nil
	}
	if prefix, err := netip.ParsePrefix(v); err == nil {
		return EntryCIDR, prefix.Masked().String(), nil
	}
	if addr, err := netip.ParseAddr(v); err == nil {
		return EntryIP, addr.String(), nil
	}
	if looksLikeIPv4(v) {
		// Digits-and-dots shapes that are not a valid IPv4 address (e.g.
		// "999.1.1.1") are almost always a typo, and such names cannot
		// resolve; reject them with a clear message instead of storing a
		// bogus "domain".
		return "", "", fmt.Errorf("%q is not a valid IPv4 address", v)
	}
	dom, err := normalizeDomain(v)
	if err != nil {
		return "", "", err
	}
	return EntryDomain, dom, nil
}

// looksLikeIPv4 reports whether v consists solely of digits and dots with
// at least one dot.
func looksLikeIPv4(v string) bool {
	if !strings.Contains(v, ".") {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= '0' && c <= '9' || c == '.') {
			return false
		}
	}
	return true
}

// normalizeDomain lowercases, strips a trailing dot, and validates that
// every label is a plain DNS label (letters, digits, hyphens, no leading or
// trailing hyphen, at most 63 bytes). Single-label names such as
// "localhost" are allowed.
func normalizeDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" {
		return "", errors.New("empty domain")
	}
	if len(s) > 253 {
		return "", errors.New("domain too long")
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid label %q in %q", label, s)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("character %q not allowed in domain %q (ASCII letters, digits and hyphens only)", string(c), s)
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("label %q must not start or end with a hyphen", label)
		}
	}
	return s, nil
}

// DefaultEntries seeds the whitelist on first run: Windows OS connectivity
// noise that would otherwise burn VirusTotal quota on every collection.
func DefaultEntries() []Entry {
	seed := []struct{ value, note string }{
		{"localhost", "loopback name"},
		{"*.local", "mDNS local names"},
		{"*.arpa", "reverse-lookup names"},
		{"*.microsoft.com", "Windows OS noise (default)"},
		{"*.windowsupdate.com", "Windows Update (default)"},
		{"*.msftconnecttest.com", "NCSI connectivity probe (default)"},
		{"*.msftncsi.com", "NCSI connectivity probe (default)"},
	}
	now := time.Now().UTC()
	entries := make([]Entry, 0, len(seed))
	for _, s := range seed {
		typ, normalized, err := ParseEntryValue(s.value)
		if err != nil {
			continue // seed values are compile-time constants; skip defensively
		}
		entries = append(entries, Entry{ID: newID(), Value: normalized, Type: typ, Note: s.note, CreatedAt: now})
	}
	return entries
}

// WhitelistStore persists entries in the data directory and answers match
// queries for IPs and domains.
type WhitelistStore struct {
	path string
	mu   sync.RWMutex
	// match-optimized views rebuilt on every mutation; lists are small.
	entries []Entry
}

func LoadWhitelist(dir string) (*WhitelistStore, error) {
	ws := &WhitelistStore{path: filepath.Join(dir, whitelistFile)}
	b, err := os.ReadFile(ws.path)
	if errors.Is(err, fs.ErrNotExist) {
		ws.entries = DefaultEntries()
		if err := ws.persist(); err != nil {
			return nil, err
		}
		return ws, nil
	}
	if err != nil {
		return nil, err
	}
	var stored struct {
		Entries []Entry `json:"entries"`
	}
	if err := json.Unmarshal(b, &stored); err != nil {
		return nil, fmt.Errorf("%s: %w", ws.path, err)
	}
	ws.entries = stored.Entries
	if ws.entries == nil {
		ws.entries = []Entry{}
	}
	return ws, nil
}

// Add normalizes value and inserts it, or updates the note when the value
// already exists. Idempotent by design so console double-clicks are safe.
func (ws *WhitelistStore) Add(value, note string) (Entry, error) {
	typ, normalized, err := ParseEntryValue(value)
	if err != nil {
		return Entry{}, err
	}
	ws.mu.Lock()
	defer ws.mu.Unlock()
	for i := range ws.entries {
		if ws.entries[i].Value == normalized {
			ws.entries[i].Note = note
			out := ws.entries[i]
			if err := ws.persist(); err != nil {
				return Entry{}, err
			}
			return out, nil
		}
	}
	entry := Entry{ID: newID(), Value: normalized, Type: typ, Note: note, CreatedAt: time.Now().UTC()}
	ws.entries = append(ws.entries, entry)
	if err := ws.persist(); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// Remove deletes the entry with the given ID.
func (ws *WhitelistStore) Remove(id string) bool {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	for i := range ws.entries {
		if ws.entries[i].ID == id {
			ws.entries = append(ws.entries[:i], ws.entries[i+1:]...)
			_ = ws.persist()
			return true
		}
	}
	return false
}

// List returns entries sorted by value.
func (ws *WhitelistStore) List() []Entry {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	out := append([]Entry(nil), ws.entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// MatchIP reports the entry covering addr (exact IP or CIDR network).
func (ws *WhitelistStore) MatchIP(addr netip.Addr) (Entry, bool) {
	addr = addr.Unmap()
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	for _, e := range ws.entries {
		switch e.Type {
		case EntryIP:
			other, err := netip.ParseAddr(e.Value)
			if err == nil && other.Unmap() == addr {
				return e, true
			}
		case EntryCIDR:
			prefix, err := netip.ParsePrefix(e.Value)
			if err == nil && prefix.Contains(addr) {
				return e, true
			}
		}
	}
	return Entry{}, false
}

// MatchDomain reports the entry covering name: an exact match or a
// wildcard entry whose base equals name or is a suffix of it.
func (ws *WhitelistStore) MatchDomain(name string) (Entry, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return Entry{}, false
	}
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	for _, e := range ws.entries {
		switch e.Type {
		case EntryDomain:
			if e.Value == name {
				return e, true
			}
		case EntryWildcard:
			base, ok := strings.CutPrefix(e.Value, "*.")
			if !ok {
				continue
			}
			if name == base || strings.HasSuffix(name, "."+base) {
				return e, true
			}
		}
	}
	return Entry{}, false
}

func (ws *WhitelistStore) persist() error {
	b, err := json.MarshalIndent(struct {
		Entries []Entry `json:"entries"`
	}{Entries: ws.entries}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(ws.path, b, 0o600)
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable for ID generation
	}
	return hex.EncodeToString(b[:])
}
