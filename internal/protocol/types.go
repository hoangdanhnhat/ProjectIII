package protocol

import "time"

const ScenarioWebshell = "webshell.v1"
const ScenarioNetstat = "netstat.v1"
const ScenarioEventlog = "eventlog.v1"

type Kind string

const (
	KindUpload          Kind = "upload"
	KindApacheLog       Kind = "apache_log"
	KindIISLog          Kind = "iis_log"
	KindNetstatSnapshot Kind = "netstat_snapshot"
	KindEventLog        Kind = "event_log"
	KindTIReport        Kind = "ti_report"
)

type Job struct {
	ID        string     `json:"id"`
	HostID    string     `json:"host_id"`
	Scenario  string     `json:"scenario"`
	Since     *time.Time `json:"since,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Status    string     `json:"status"`
	Reason    string     `json:"reason,omitempty"`
	// TIStatus/TIReason track the server-side threat-intel enrichment of
	// netstat.v1 jobs (running -> completed | partial | skipped | failed).
	// Empty means enrichment has not run.
	TIStatus  string     `json:"ti_status,omitempty"`
	TIReason  string     `json:"ti_reason,omitempty"`
	Artifacts []Artifact `json:"artifacts"`
}

type Artifact struct {
	ID          string    `json:"id"`
	Kind        Kind      `json:"kind"`
	Source      string    `json:"source"`
	Reason      string    `json:"reason"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	Mode        string    `json:"mode"`
	ModifiedAt  time.Time `json:"modified_at"`
	CollectedAt time.Time `json:"collected_at"`
	StoredAt    string    `json:"stored_at"`
}

type Result struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}
