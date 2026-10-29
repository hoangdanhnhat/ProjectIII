package collector

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type logCandidate struct {
	path    string
	modTime time.Time
	found   bool
}

// ExpandLogPatterns expands glob patterns, removes duplicates, and keeps the
// max most recently modified paths. Literal paths are always kept, even if
// they do not exist, so a missing log is reported as a collection error
// instead of being silently ignored. A pattern that matches nothing (for
// example the IIS wildcard on a host with no IIS logs) is ignored.
func ExpandLogPatterns(patterns []string, max int) (paths []string, dropped int) {
	seen := make(map[string]struct{})
	var candidates []logCandidate
	add := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		c := logCandidate{path: path}
		if info, err := os.Stat(path); err == nil {
			c.modTime, c.found = info.ModTime(), true
		}
		candidates = append(candidates, c)
	}
	for _, raw := range patterns {
		pattern := strings.TrimSpace(raw)
		if pattern == "" {
			continue
		}
		if strings.ContainsAny(pattern, "*?") {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				// Malformed pattern: treat it as a literal path so the job
				// reports a concrete error instead of silently dropping it.
				add(pattern)
				continue
			}
			for _, match := range matches {
				add(match)
			}
			continue
		}
		add(pattern)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.found != b.found {
			return a.found
		}
		if a.found && !a.modTime.Equal(b.modTime) {
			return a.modTime.After(b.modTime)
		}
		return a.path < b.path
	})
	if len(candidates) > max {
		dropped = len(candidates) - max
		candidates = candidates[:max]
	}
	paths = make([]string, len(candidates))
	for i, c := range candidates {
		paths[i] = c.path
	}
	return paths, dropped
}
