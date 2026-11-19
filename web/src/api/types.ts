// Hand-written mirrors of the Go API structs (internal/protocol and
// internal/ti). This is the single source of truth for payload shapes; keep
// it in sync when the server contract changes.

export interface Meta {
  host_id: string;
  hosts: string[];
  roles: HostRole[];
  scenarios: string[];
}

export type Kind =
  | "upload"
  | "apache_log"
  | "iis_log"
  | "netstat_snapshot"
  | "event_log"
  | "ti_report"
  | "host_role"
  | "memory_image"
  | "memory_manifest"
  | "volatility_report"
  | "volatility_plugin";

export type JobStatus =
  | "queued"
  | "running"
  | "completed"
  | "partial"
  | "failed"
  | "skipped"
  | "needs_configuration";

export type TIStatus =
  | "running"
  | "completed"
  | "partial"
  | "skipped"
  | "failed"
  | "interrupted";

export type Verdict =
  | "blacklisted"
  | "malicious"
  | "suspicious"
  | "clean"
  | "unrated"
  | "whitelisted"
  | "private"
  | "skipped";

export interface Artifact {
  id: string;
  kind: Kind;
  source: string;
  reason: string;
  sha256: string;
  size: number;
  mode: string;
  modified_at: string;
  collected_at: string;
  stored_at: string;
}

export interface Job {
  id: string;
  host_id: string;
  scenario: string;
  since?: string | null;
  created_at: string;
  started_at?: string | null;
  ended_at?: string | null;
  status: JobStatus;
  reason?: string;
  ti_status?: TIStatus | "";
  ti_reason?: string;
  volatility_status?: VolatilityStatus | "";
  volatility_reason?: string;
  volatility_image?: string;
  artifacts: Artifact[];
}

export interface VTInfo {
  queried?: boolean;
  from_cache?: boolean;
  detections?: string;
  reputation?: number;
  as_owner?: string;
  country?: string;
  link?: string;
  retrieved_at?: string;
  error?: string;
}

export interface Indicator {
  type: "ip" | "domain";
  value: string;
  classification: "public" | "private" | "internal" | "whitelisted" | "blacklisted";
  verdict: Verdict;
  whitelist_match?: string;
  blacklist_match?: string;
  domains?: string[];
  processes?: string[];
  connections?: number;
  vt?: VTInfo;
}

export interface TISummary {
  total: number;
  blacklisted: number;
  malicious: number;
  suspicious: number;
  clean: number;
  unrated: number;
  whitelisted: number;
  private: number;
  skipped: number;
}

export interface TIReport {
  schema_version: number;
  job_id: string;
  host_id: string;
  generated_at: string;
  source_artifact: string;
  snapshot_generated_at: string;
  vt_enabled: boolean;
  vt_queried: number;
  vt_cache_hits: number;
  vt_errors: number;
  max_queries: number;
  summary: TISummary;
  indicators: Indicator[];
}

export interface SnapshotConnection {
  proto: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  state?: string;
  pid: number;
  process?: string;
  domains?: string[];
}

export interface DNSRecord {
  name: string;
  type: string;
  ttl?: number;
  data: string;
}

export interface Snapshot {
  schema_version: number;
  generated_at: string;
  connections: SnapshotConnection[];
  dns_cache?: DNSRecord[];
}

export type HostRole =
  | "domain_controller"
  | "web_server"
  | "workstation"
  | "database_server"
  | "mail_server"
  | "dns_server"
  | "dhcp_server";

export type HostRoleTier = "confirmed" | "probable" | "possible";

export type HostRoleStrength = "definitive" | "strong" | "supporting";

export interface HostRoleEvidence {
  strength: HostRoleStrength;
  source: string;
  detail: string;
}

export interface HostRoleResult {
  role: HostRole;
  confidence: number;
  tier: HostRoleTier;
  evidence: HostRoleEvidence[];
}

export interface HostRoleProfile {
  schema_version: number;
  generated_at: string;
  method: string;
  host: {
    hostname: string;
    product_type?: string;
    host_class: "domain_controller" | "server" | "workstation" | "unknown";
    os_name?: string;
    os_build?: string;
  };
  primary_role?: HostRole;
  roles: HostRoleResult[];
  probe_errors?: Array<{ source: string; detail: string }>;
}

/** Mirrors internal/collector/memory.Manifest (schema version 1). */
export interface MemoryManifest {
  schema_version: number;
  scenario: string;
  host_id: string;
  job_id: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  tool: {
    name: string;
    version?: string;
    path: string;
    sha256: string;
    args: string[];
  };
  memory_total_bytes: number;
  disk_free_bytes: number;
  image?: {
    path: string;
    size: number;
    sha256: string;
  };
  result: {
    status: "completed" | "failed";
    error?: string;
    exit_code: number;
    stdout_tail?: string;
    stderr_tail?: string;
  };
  notes: string[];
}

export type HostStatus = "online" | "stale" | "offline" | "never_seen";

export interface HostOS {
  name?: string;
  build?: string;
  product_type?: string;
  host_class?: string;
  platform?: string;
  arch?: string;
}

export interface HostRoleSummary {
  role: HostRole;
  confidence: number;
  tier: HostRoleTier;
}

export interface Host {
  schema_version: number;
  host_id: string;
  hostname?: string;
  os: HostOS;
  auto_roles: HostRoleSummary[];
  manual_roles?: HostRole[];
  effective_roles: HostRole[];
  role_source: "auto" | "manual";
  role_revision: number;
  applied_role_revision: number;
  role_checked_at?: string | null;
  role_error?: string;
  manual_note?: string;
  manual_updated_at?: string | null;
  created_at: string;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  agent_version?: string;
  status: HostStatus;
}

export interface SetHostRolesInput {
  roles: HostRole[];
  note?: string;
}

export type ListName = "whitelist" | "blacklist";

export interface ListEntry {
  id: string;
  value: string;
  type: "ip" | "cidr" | "domain" | "domain_wildcard";
  note?: string;
  created_at: string;
}

export type VolatilityStatus =
  | "running"
  | "completed"
  | "partial"
  | "failed"
  | "skipped"
  | "interrupted";

export interface VolatilityPluginResult {
  name: string;
  status: "completed" | "failed" | "oversized";
  rows: number;
  duration_ms: number;
  size: number;
  artifact_id?: string;
  error?: string;
}

export interface VolatilityReport {
  schema_version: number;
  job_id: string;
  host_id: string;
  generated_at: string;
  engine: {
    name: string;
    version: string;
    wrapper_commit: string;
  };
  image: {
    artifact_id: string;
    sha256: string;
    size: number;
  };
  plugins: VolatilityPluginResult[];
  summary: {
    requested: number;
    completed: number;
    failed: number;
    oversized: number;
    rows: number;
  };
  notes: string[];
  log_tail?: string;
}

export interface TISettings {
  vt: {
    configured: boolean;
    key_preview: string;
    auto_enrich: boolean;
    rate_per_min: number;
    max_queries_per_job: number;
  };
  whitelist: { entries: ListEntry[] };
  blacklist: { entries: ListEntry[] };
}

export interface CreateJobInput {
  host_id: string;
  scenario: string;
  since?: string;
}

export interface UpdateTISettingsInput {
  vt_api_key?: string;
  vt_auto_enrich?: boolean;
  vt_rate_per_min?: number;
  vt_max_queries_per_job?: number;
}
