package memory

import (
	"encoding/json"
	"time"
)

// Manifest is the schema-versioned companion artifact of one memory capture.
// It records the tool identity and digest, the exact argv, the image size and
// SHA-256, and the outcome, so the image can be verified and attributed
// without trusting the agent's reason line.
type Manifest struct {
	SchemaVersion    int       `json:"schema_version"`
	Scenario         string    `json:"scenario"`
	HostID           string    `json:"host_id"`
	JobID            string    `json:"job_id"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	DurationMS       int64     `json:"duration_ms"`
	Tool             Tool      `json:"tool"`
	MemoryTotalBytes int64     `json:"memory_total_bytes"`
	DiskFreeBytes    int64     `json:"disk_free_bytes"`
	Image            *Image    `json:"image,omitempty"`
	Result           Result    `json:"result"`
	Notes            []string  `json:"notes"`
}

// Tool identifies the acquisition binary that ran.
type Tool struct {
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Path    string   `json:"path"`
	SHA256  string   `json:"sha256"`
	Args    []string `json:"args"`
}

// Image describes the captured file.
type Image struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Result is the outcome of the tool invocation.
type Result struct {
	Status     string `json:"status"` // completed | failed
	Error      string `json:"error,omitempty"`
	ExitCode   int    `json:"exit_code"`
	StdoutTail string `json:"stdout_tail,omitempty"`
	StderrTail string `json:"stderr_tail,omitempty"`
}

// Render serializes a manifest as indented JSON. Notes is always an array so
// analysis tooling never has to handle null.
func Render(m Manifest) []byte {
	if m.Notes == nil {
		m.Notes = []string{}
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		// These types cannot fail to marshal; keep the failure loud anyway.
		return []byte(`{"error":"render failed"}`)
	}
	return data
}
