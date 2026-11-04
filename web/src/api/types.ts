// Hand-written mirrors of the Go API structs (internal/protocol and
// internal/ti). This is the single source of truth for payload shapes; keep
// it in sync when the server contract changes.

export interface Meta {
  host_id: string;
  scenarios: string[];
}

export type Kind =
  | "upload"
  | "apache_log"
  | "iis_log"
  | "netstat_snapshot"
  | "event_log"
  | "ti_report";

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

export type ListName = "whitelist" | "blacklist";

export interface ListEntry {
  id: string;
  value: string;
  type: "ip" | "cidr" | "domain" | "domain_wildcard";
  note?: string;
  created_at: string;
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
