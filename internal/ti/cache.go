package ti

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// cacheTTL bounds how long a VirusTotal answer is reused across collections
// before a fresh query is required.
const cacheTTL = 24 * time.Hour

const cacheFile = "ti_cache.json"

// Cache is a persistent ip/domain -> verdict store shared by all enrichment
// runs, so repeated indicators cost no VirusTotal quota.
type Cache struct {
	path    string
	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	Result   VTResult  `json:"result"`
	CachedAt time.Time `json:"cached_at"`
}

func LoadCache(dir string) *Cache {
	c := &Cache{path: filepath.Join(dir, cacheFile), entries: map[string]cacheEntry{}}
	b, err := os.ReadFile(c.path)
	if err != nil {
		return c // missing or unreadable cache starts empty
	}
	var stored struct {
		Entries map[string]cacheEntry `json:"entries"`
	}
	if json.Unmarshal(b, &stored) == nil && stored.Entries != nil {
		c.entries = stored.Entries
	}
	c.prune()
	return c
}

func (c *Cache) get(key string) (VTResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Since(e.CachedAt) > cacheTTL {
		return VTResult{}, false
	}
	return e.Result, true
}

func (c *Cache) put(key string, res VTResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{Result: res, CachedAt: time.Now().UTC()}
}

// Save persists the cache when it holds entries; an empty cache is not
// written.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) == 0 {
		return nil
	}
	c.pruneLocked()
	b, err := json.MarshalIndent(struct {
		Entries map[string]cacheEntry `json:"entries"`
	}{Entries: c.entries}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(c.path, b, 0o600)
}

func (c *Cache) prune() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked()
}

func (c *Cache) pruneLocked() {
	now := time.Now()
	for k, e := range c.entries {
		if now.Sub(e.CachedAt) > cacheTTL {
			delete(c.entries, k)
		}
	}
}
