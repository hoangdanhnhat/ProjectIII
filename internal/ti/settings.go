// Package ti implements the server-side threat-intelligence automation for
// netstat.v1 collections: extracting public IPs and cached domains from a
// snapshot, filtering them against non-routable ranges and an
// operator-managed whitelist, and checking the remainder against
// VirusTotal. The enriched verdicts are stored as a ti_report artifact
// next to the raw snapshot; the raw snapshot bytes are never modified.
package ti

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// Defaults for a fresh install. The VirusTotal free tier allows 4 requests
// per minute, and each public collection is capped so one busy snapshot
// cannot exhaust the daily quota.
const (
	DefaultRatePerMin = 4
	DefaultMaxQueries = 40
	defaultBaseURL    = "https://www.virustotal.com"
)

const settingsFile = "ti_config.json"

// Settings is the operator-managed TI configuration persisted in the data
// directory with 0600 permissions. The API key never leaves the server; the
// console only receives a masked preview.
type Settings struct {
	VTAPIKey     string `json:"vt_api_key,omitempty"`
	VTAutoEnrich bool   `json:"vt_auto_enrich"`
	VTRatePerMin int    `json:"vt_rate_per_min"`
	VTMaxQueries int    `json:"vt_max_queries_per_job"`
	// VTBaseURL defaults to VirusTotal and exists so tests can point the
	// client at a fake server; it is not exposed in the console.
	VTBaseURL string `json:"vt_base_url,omitempty"`
}

func DefaultSettings() Settings {
	return Settings{VTAutoEnrich: true, VTRatePerMin: DefaultRatePerMin, VTMaxQueries: DefaultMaxQueries}
}

// BaseURL returns the API base with no trailing slash.
func (s Settings) BaseURL() string {
	u := s.VTBaseURL
	if u == "" {
		u = defaultBaseURL
	}
	for len(u) > 0 && u[len(u)-1] == '/' {
		u = u[:len(u)-1]
	}
	return u
}

// SettingsStore loads and saves Settings with an atomic rename, filling in
// defaults for fields missing from older files.
type SettingsStore struct {
	path string
	mu   sync.Mutex
	s    Settings
}

func LoadSettings(dir string) (*SettingsStore, error) {
	st := &SettingsStore{path: filepath.Join(dir, settingsFile), s: DefaultSettings()}
	b, err := os.ReadFile(st.path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := st.persist(); err != nil {
			return nil, err
		}
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &st.s); err != nil {
		return nil, fmt.Errorf("%s: %w", st.path, err)
	}
	st.s.VTRatePerMin = clampDefault(st.s.VTRatePerMin, DefaultRatePerMin)
	st.s.VTMaxQueries = clampDefault(st.s.VTMaxQueries, DefaultMaxQueries)
	return st, nil
}

func clampDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// Get returns a copy of the current settings.
func (st *SettingsStore) Get() Settings {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.s
}

// Update applies fn under the store lock and persists the result.
func (st *SettingsStore) Update(fn func(*Settings)) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.s)
	return st.persist()
}

func (st *SettingsStore) persist() error {
	b, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(st.path, b, 0o600)
}

// writeFileAtomic writes via a temp file + rename so a crash never leaves a
// half-written store behind. Parent directory must exist.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
