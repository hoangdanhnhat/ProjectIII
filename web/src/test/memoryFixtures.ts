import type { Artifact, Job, MemoryManifest, VolatilityReport } from "../api/types";
import { JOB } from "./fixtures";

const MEMORY_SHA = "5b80372d26f061118d47d59c98768d328a83cf55ba31293ff03f245c058e6b4b";

export const MEMORY_IMAGE: Artifact = {
  id: "mem-image",
  kind: "memory_image",
  source: "C:\\DFIR\\memory\\memory-win-web01-mem-job-0001.raw",
  reason: "full physical memory image captured with winpmem",
  sha256: MEMORY_SHA,
  size: 2147418112,
  mode: "-rw-rw-rw-",
  modified_at: "2026-11-18T06:31:00Z",
  collected_at: "2026-11-18T06:31:00Z",
  stored_at: "artifacts/mem-job-0001/mem-image",
};

export const MEMORY_MANIFEST_ARTIFACT: Artifact = {
  id: "mem-manifest",
  kind: "memory_manifest",
  source: "memory_capture.json",
  reason: "memory capture manifest: tool identity, image hash and capture result",
  sha256: "e".repeat(64),
  size: 2473,
  mode: "synthesized",
  modified_at: "2026-11-18T06:31:00Z",
  collected_at: "2026-11-18T06:31:00Z",
  stored_at: "artifacts/mem-job-0001/mem-manifest",
};

export const MEMORY_JOB: Job = {
  ...JOB,
  id: "mem-job-0001",
  host_id: "win-web01",
  scenario: "memory.v1",
  status: "completed",
  reason: "collected 2 artifacts, 0 errors",
  ti_status: "",
  volatility_status: "completed",
  volatility_reason: "2/2 plugins completed, 3 rows",
  volatility_image: "mem-image",
  artifacts: [MEMORY_IMAGE, MEMORY_MANIFEST_ARTIFACT],
};

export const VOL_REPORT_ARTIFACT: Artifact = {
  id: "vol-report",
  kind: "volatility_report",
  source: "volatility_report.json",
  reason: "Volatility 3 memory analysis summary (server-generated)",
  sha256: "f".repeat(64),
  size: 2048,
  mode: "synthesized",
  modified_at: "2026-11-18T06:32:00Z",
  collected_at: "2026-11-18T06:32:00Z",
  stored_at: "artifacts/mem-job-0001/vol-report",
};

export const VOL_PSLIST_ARTIFACT: Artifact = {
  id: "vol-pslist",
  kind: "volatility_plugin",
  source: "windows.pslist.PsList.jsonl",
  reason: "Volatility 3 plugin windows.pslist.PsList output (JSONL, server-generated)",
  sha256: "1".repeat(64),
  size: 512,
  mode: "synthesized",
  modified_at: "2026-11-18T06:32:00Z",
  collected_at: "2026-11-18T06:32:00Z",
  stored_at: "artifacts/mem-job-0001/vol-pslist",
};

export const VOL_MALFIND_ARTIFACT: Artifact = {
  id: "vol-malfind",
  kind: "volatility_plugin",
  source: "windows.malware.malfind.Malfind.jsonl",
  reason: "Volatility 3 plugin windows.malware.malfind.Malfind output (JSONL, server-generated)",
  sha256: "2".repeat(64),
  size: 256,
  mode: "synthesized",
  modified_at: "2026-11-18T06:32:00Z",
  collected_at: "2026-11-18T06:32:00Z",
  stored_at: "artifacts/mem-job-0001/vol-malfind",
};

MEMORY_JOB.artifacts = [
  MEMORY_IMAGE,
  MEMORY_MANIFEST_ARTIFACT,
  VOL_PSLIST_ARTIFACT,
  VOL_MALFIND_ARTIFACT,
  VOL_REPORT_ARTIFACT,
];

export const VOL_REPORT: VolatilityReport = {
  schema_version: 1,
  job_id: "mem-job-0001",
  host_id: "win-web01",
  generated_at: "2026-11-18T06:32:00Z",
  engine: {
    name: "volatility3",
    version: "2.28.2",
    wrapper_commit: "0fbc6d8de9c859e5270bde2bfb5ee15cfe82497a",
  },
  image: {
    artifact_id: "mem-image",
    sha256: MEMORY_SHA,
    size: 2147418112,
  },
  plugins: [
    {
      name: "windows.pslist.PsList",
      status: "completed",
      rows: 2,
      duration_ms: 1480,
      size: 512,
      artifact_id: "vol-pslist",
    },
    {
      name: "windows.malware.malfind.Malfind",
      status: "completed",
      rows: 1,
      duration_ms: 13750,
      size: 256,
      artifact_id: "vol-malfind",
    },
  ],
  summary: { requested: 2, completed: 2, failed: 0, oversized: 0, rows: 3 },
  notes: [
    "analysis output is derived evidence; the memory image itself is unchanged",
    "captured on a live system: memory may change during acquisition",
  ],
};

export const VOL_PSLIST_ROWS = [
  '{"PID":4,"ImageFileName":"System","Offset(V)":218852697157696}',
  '{"PID":412,"ImageFileName":"explorer.exe","Offset(V)":218852697999999}',
].join("\n");

export const VOL_MALFIND_ROWS = [
  '{"PID":412,"Process":"explorer.exe","Protection":"PAGE_EXECUTE_READWRITE"}',
].join("\n");


export const MEMORY_MANIFEST: MemoryManifest = {
  schema_version: 1,
  scenario: "memory.v1",
  host_id: "win-web01",
  job_id: "mem-job-0001",
  started_at: "2026-11-18T06:30:50Z",
  finished_at: "2026-11-18T06:31:00Z",
  duration_ms: 15071,
  tool: {
    name: "winpmem",
    version: "4.0.1",
    path: "C:\\dfir\\winpmem64.exe",
    sha256: "25dafa5986f2bf6537c2f637c843219b274724d279240efd443452f4a9b2bec2",
    args: ["C:\\dfir\\memory\\memory-win-web01-mem-job-0001.raw"],
  },
  memory_total_bytes: 2147012608,
  disk_free_bytes: 19447558144,
  image: {
    path: "C:\\dfir\\memory\\memory-win-web01-mem-job-0001.raw",
    size: 2147418112,
    sha256: MEMORY_SHA,
  },
  result: {
    status: "completed",
    exit_code: 1,
    stdout_tail: "WinPmem64\nmax_physical_memory_ 0x7fff0000\n",
  },
  notes: [
    "raw physical memory; pagefile and hibernation file are not included",
    "captured on a live system: memory may change during acquisition",
    "winpmem reports a completed acquisition with exit code 1 (0 is not used)",
  ],
};
