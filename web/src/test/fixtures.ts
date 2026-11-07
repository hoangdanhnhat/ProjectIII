import type { HostRoleProfile, Job, Snapshot, TISettings, TIReport } from "../api/types";

export const META = { host_id: "lab-ubuntu", scenarios: ["webshell.v1", "netstat.v1", "eventlog.v1"] };

export const JOB: Job = {
  id: "98a997a4fdfe6edcdee98d71ef8298c8",
  host_id: "lab-ubuntu",
  scenario: "netstat.v1",
  created_at: "2026-11-05T08:00:00Z",
  started_at: "2026-11-05T08:00:01Z",
  ended_at: "2026-11-05T08:00:05Z",
  status: "completed",
  ti_status: "completed",
  artifacts: [
    {
      id: "snap1",
      kind: "netstat_snapshot",
      source: "netstat_snapshot.json",
      reason: "snapshot",
      sha256: "a".repeat(64),
      size: 1234,
      mode: "synthesized",
      modified_at: "2026-11-05T08:00:04Z",
      collected_at: "2026-11-05T08:00:04Z",
      stored_at: "artifacts/job/snap1",
    },
    {
      id: "rep1",
      kind: "ti_report",
      source: "ti_report.json",
      reason: "enrichment",
      sha256: "b".repeat(64),
      size: 2345,
      mode: "synthesized",
      modified_at: "2026-11-05T08:00:05Z",
      collected_at: "2026-11-05T08:00:05Z",
      stored_at: "artifacts/job/rep1",
    },
  ],
};

export const HOST_ROLE: HostRoleProfile = {
  schema_version: 1,
  generated_at: "2026-11-05T08:00:04Z",
  method: "registry+service+filesystem-metadata",
  host: {
    hostname: "WIN-WEB01",
    product_type: "ServerNT",
    host_class: "server",
    os_name: "Windows Server 2022 Standard",
    os_build: "20348.1000",
  },
  primary_role: "web_server",
  roles: [
    {
      role: "web_server",
      confidence: 1,
      tier: "confirmed",
      evidence: [
        {
          strength: "definitive",
          source: "file:%SystemRoot%\\System32\\inetsrv\\config\\applicationHost.config",
          detail: "IIS configuration file present",
        },
        {
          strength: "strong",
          source: "service:W3SVC",
          detail: "service present, Start=auto",
        },
      ],
    },
    {
      role: "file_server",
      confidence: 0.65,
      tier: "probable",
      evidence: [
        {
          strength: "definitive",
          source: "registry:HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares",
          detail: "non-default SMB share(s): Deploy",
        },
      ],
    },
  ],
};

export const ROLE_JOB: Job = {
  id: "role-job-0001",
  host_id: "win-web01",
  scenario: "hostrole.v1",
  created_at: "2026-11-05T08:00:00Z",
  started_at: "2026-11-05T08:00:01Z",
  ended_at: "2026-11-05T08:00:04Z",
  status: "completed",
  artifacts: [
    {
      id: "role1",
      kind: "host_role",
      source: "host_role.json",
      reason: "host role profile",
      sha256: "c".repeat(64),
      size: 3456,
      mode: "synthesized",
      modified_at: "2026-11-05T08:00:04Z",
      collected_at: "2026-11-05T08:00:04Z",
      stored_at: "artifacts/role-job/role1",
    },
  ],
};

export const SNAPSHOT: Snapshot = {
  schema_version: 2,
  generated_at: "2026-11-05T08:00:04Z",
  connections: [
    {
      proto: "tcp",
      local_addr: "10.0.0.5",
      local_port: 51000,
      remote_addr: "93.184.216.34",
      remote_port: 443,
      state: "ESTABLISHED",
      pid: 4020,
      process: "chrome.exe",
      domains: ["portal.example.com"],
    },
    {
      proto: "tcp",
      local_addr: "10.0.0.5",
      local_port: 51001,
      remote_addr: "10.0.0.9",
      remote_port: 445,
      state: "ESTABLISHED",
      pid: 4,
      process: "System",
    },
  ],
  dns_cache: [
    { name: "portal.example.com", type: "CNAME", ttl: 47, data: "cdn.example.net" },
    { name: "cdn.example.net", type: "A", ttl: 47, data: "93.184.216.34" },
  ],
};

export const REPORT: TIReport = {
  schema_version: 2,
  job_id: JOB.id,
  host_id: "lab-ubuntu",
  generated_at: "2026-11-05T08:00:05Z",
  source_artifact: "snap1",
  snapshot_generated_at: SNAPSHOT.generated_at,
  vt_enabled: true,
  vt_queried: 2,
  vt_cache_hits: 0,
  vt_errors: 0,
  max_queries: 40,
  summary: {
    total: 4,
    blacklisted: 0,
    malicious: 1,
    suspicious: 0,
    clean: 1,
    unrated: 0,
    whitelisted: 1,
    private: 1,
    skipped: 0,
  },
  indicators: [
    {
      type: "ip",
      value: "93.184.216.34",
      classification: "public",
      verdict: "malicious",
      domains: ["portal.example.com"],
      processes: ["chrome.exe (4020)"],
      connections: 1,
      vt: {
        queried: true,
        detections: "7/92",
        link: "https://www.virustotal.com/gui/ip-address/93.184.216.34",
      },
    },
    {
      type: "ip",
      value: "10.0.0.9",
      classification: "private",
      verdict: "private",
      processes: ["System (4)"],
      connections: 1,
    },
    {
      type: "domain",
      value: "cdn.example.net",
      classification: "public",
      verdict: "clean",
      vt: { queried: true, detections: "0/80" },
    },
    {
      type: "domain",
      value: "update.microsoft.com",
      classification: "whitelisted",
      verdict: "whitelisted",
      whitelist_match: "*.microsoft.com",
    },
  ],
};

export const TI_SETTINGS: TISettings = {
  vt: {
    configured: true,
    key_preview: "••••abcd",
    auto_enrich: true,
    rate_per_min: 4,
    max_queries_per_job: 40,
  },
  whitelist: {
    entries: [
      {
        id: "w1",
        value: "*.microsoft.com",
        type: "domain_wildcard",
        note: "Windows noise",
        created_at: "2026-11-01T00:00:00Z",
      },
      { id: "w2", value: "localhost", type: "domain", created_at: "2026-11-01T00:00:00Z" },
    ],
  },
  blacklist: {
    entries: [
      {
        id: "b1",
        value: "203.0.113.66",
        type: "ip",
        note: "known C2",
        created_at: "2026-11-02T00:00:00Z",
      },
    ],
  },
};
