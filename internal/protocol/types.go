package protocol

import "time"

const ScenarioWebshell = "webshell.v1"
const ScenarioNetstat = "netstat.v1"
const ScenarioEventlog = "eventlog.v1"
const ScenarioHostRole = "hostrole.v1"

type Kind string

const (
	KindUpload          Kind = "upload"
	KindApacheLog       Kind = "apache_log"
	KindIISLog          Kind = "iis_log"
	KindNetstatSnapshot Kind = "netstat_snapshot"
	KindEventLog        Kind = "event_log"
	KindTIReport        Kind = "ti_report"
	KindHostRole        Kind = "host_role"
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

// HostOS describes the operating system a managed host reported.
type HostOS struct {
	Name        string `json:"name,omitempty"`
	Build       string `json:"build,omitempty"`
	ProductType string `json:"product_type,omitempty"`
	HostClass   string `json:"host_class,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Arch        string `json:"arch,omitempty"`
}

// HostRoleSummary is one automatically detected role. Evidence stays in the
// host_role artifact; the inventory only needs the confidence band.
type HostRoleSummary struct {
	Role       string  `json:"role"`
	Confidence float64 `json:"confidence"`
	Tier       string  `json:"tier"`
}

// Host is one managed machine in the inventory. EffectiveRoles is ManualRoles
// when an override exists, otherwise the automatic role IDs. Status is
// derived from LastSeenAt and is not part of the durable state.
type Host struct {
	SchemaVersion       int               `json:"schema_version"`
	ID                  string            `json:"host_id"`
	Hostname            string            `json:"hostname,omitempty"`
	OS                  HostOS            `json:"os"`
	AutoRoles           []HostRoleSummary `json:"auto_roles"`
	ManualRoles         []string          `json:"manual_roles,omitempty"`
	EffectiveRoles      []string          `json:"effective_roles"`
	RoleSource          string            `json:"role_source"`
	RoleRevision        int               `json:"role_revision"`
	AppliedRoleRevision int               `json:"applied_role_revision"`
	RoleCheckedAt       *time.Time        `json:"role_checked_at,omitempty"`
	RoleError           string            `json:"role_error,omitempty"`
	ManualNote          string            `json:"manual_note,omitempty"`
	ManualUpdatedAt     *time.Time        `json:"manual_updated_at,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	FirstSeenAt         *time.Time        `json:"first_seen_at,omitempty"`
	LastSeenAt          *time.Time        `json:"last_seen_at,omitempty"`
	AgentVersion        string            `json:"agent_version,omitempty"`
	Status              string            `json:"status"`
}

// HostReport is the agent's heartbeat. RoleCheckedAt is nil when the agent did
// not run detection for this heartbeat (for example during a manual override);
// the server then keeps the previous automatic result.
type HostReport struct {
	Hostname            string            `json:"hostname,omitempty"`
	OS                  HostOS            `json:"os"`
	AutoRoles           []HostRoleSummary `json:"auto_roles,omitempty"`
	RoleCheckedAt       *time.Time        `json:"role_checked_at,omitempty"`
	RoleError           string            `json:"role_error,omitempty"`
	AppliedRoleRevision int               `json:"applied_role_revision"`
	AgentVersion        string            `json:"agent_version,omitempty"`
}

// HostAssignment is the server's heartbeat response: the authoritative manual
// override and its revision. An empty ManualRoles means automatic mode.
type HostAssignment struct {
	HostID       string    `json:"host_id"`
	ManualRoles  []string  `json:"manual_roles,omitempty"`
	RoleRevision int       `json:"role_revision"`
	ServerTime   time.Time `json:"server_time"`
}
