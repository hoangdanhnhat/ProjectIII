// Package volatility runs Volatility 3 plugins against a memory image with the
// pinned VolGolangWrapper binary and turns the per-plugin JSONL files into a
// versioned report. The analysis is server-side and read-only: the source
// image is never modified, and every output is stored as a derived artifact.
//
// # Subprocess policy
//
// This is the third subprocess in the codebase (wevtutil, the acquisition
// tool, and now the wrapper). The wrapper and Volatility are fixed, vetted
// tools resolved from explicit paths configured on the server; arguments are
// built by this package only, no shell is involved, the child gets a filtered
// environment without operator/agent tokens, and the whole process group is
// killed on timeout.
package volatility

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Statuses stored on the job, mirroring the TI enrichment statuses.
const (
	StatusRunning     = "running"
	StatusCompleted   = "completed"
	StatusPartial     = "partial"
	StatusFailed      = "failed"
	StatusSkipped     = "skipped"
	StatusInterrupted = "interrupted"
)

const (
	// DefaultEngineVersion is the pinned PyPI release, which is built from the
	// volatility3 stable branch (v2.28.2 at the time of writing).
	DefaultEngineVersion = "2.28.2"
	// DefaultWrapperCommit is the pinned upstream commit of VolGolangWrapper.
	DefaultWrapperCommit = "0fbc6d8de9c859e5270bde2bfb5ee15cfe82497a"
)

// DefaultPlugins is the curated Windows plugin set. It deliberately excludes
// the very slow or very large plugins (filescan, handles, vadinfo, timeliner)
// and plugins that need per-run arguments. A site can override the list with
// the server's -vol-plugins flag.
var DefaultPlugins = []string{
	"windows.info.Info",
	"windows.pslist.PsList",
	"windows.pstree.PsTree",
	"windows.cmdline.CmdLine",
	"windows.netscan.NetScan",
	"windows.dlllist.DllList",
	"windows.modules.Modules",
	"windows.svcscan.SvcScan",
	"windows.malware.malfind.Malfind",
	"windows.registry.hivelist.HiveList",
	"windows.amcache.Amcache",
	"windows.getsids.GetSIDs",
}

// LoadPlugins returns the plugin list from path, or the embedded default when
// path is empty. Blank lines and lines starting with # are ignored.
func LoadPlugins(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return append([]string(nil), DefaultPlugins...), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plugin list: %w", err)
	}
	var plugins []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		plugins = append(plugins, line)
	}
	if len(plugins) == 0 {
		return nil, fmt.Errorf("plugin list %s is empty", path)
	}
	return plugins, nil
}

// ImageRef identifies the source artifact in the report.
type ImageRef struct {
	ArtifactID string `json:"artifact_id"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

// Engine records which tools produced an analysis.
type Engine struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	WrapperCommit string `json:"wrapper_commit"`
}

// PluginResult is one requested plugin's outcome.
type PluginResult struct {
	Name       string `json:"name"`
	Status     string `json:"status"` // completed | failed | oversized
	Rows       int    `json:"rows"`
	DurationMS int64  `json:"duration_ms"`
	Size       int64  `json:"size"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Summary aggregates the plugin results.
type Summary struct {
	Requested int `json:"requested"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Oversized int `json:"oversized"`
	Rows      int `json:"rows"`
}

// Report is the schema-versioned analysis summary stored next to the outputs.
type Report struct {
	SchemaVersion int            `json:"schema_version"`
	JobID         string         `json:"job_id"`
	HostID        string         `json:"host_id"`
	GeneratedAt   time.Time      `json:"generated_at"`
	Engine        Engine         `json:"engine"`
	Image         ImageRef       `json:"image"`
	Plugins       []PluginResult `json:"plugins"`
	Summary       Summary        `json:"summary"`
	Notes         []string       `json:"notes"`
	LogTail       string         `json:"log_tail,omitempty"`
}

// PluginOutput is one successful plugin's JSONL bytes, ready to be stored as
// an artifact by the server.
type PluginOutput struct {
	Name string
	Data []byte
	Rows int
	Size int64
}

// Input is one analysis request.
type Input struct {
	JobID     string
	HostID    string
	ImagePath string
	Image     ImageRef
}

// Config configures a Runner. Paths are absolute inside the server container.
type Config struct {
	VolPath     string        // Volatility 3 executable
	WrapperPath string        // VolGolangWrapper binary
	SymbolsDir  string        // -s for Volatility; persisted symbol cache
	CacheDir    string        // --cache-path; persisted identifier cache
	WorkRoot    string        // parent for per-run work directories
	Plugins     []string      // effective plugin list
	CPUs        string        // taskset CPU list, e.g. "0-3"; empty disables
	Timeout     time.Duration // one analysis run
	MaxOutput   int64         // per-plugin output cap
	Now         func() time.Time
}
