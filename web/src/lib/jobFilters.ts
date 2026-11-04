import type { Job } from "../api/types";

export type FilterId = "all" | "active" | "completed" | "attention";

export const FILTERS: Array<{ id: FilterId; label: string; match: (job: Job) => boolean }> = [
  { id: "all", label: "All", match: () => true },
  { id: "active", label: "Active", match: (job) => job.status === "queued" || job.status === "running" },
  { id: "completed", label: "Completed", match: (job) => job.status === "completed" },
  {
    id: "attention",
    label: "Attention",
    match: (job) => ["partial", "failed", "skipped", "needs_configuration"].includes(job.status),
  },
];

export function matchesQuery(job: Job, query: string): boolean {
  if (!query) return true;
  const haystack = [
    job.id,
    job.host_id,
    job.scenario,
    job.status,
    job.reason ?? "",
    job.ti_status ?? "",
    ...(job.artifacts ?? []).map((artifact) => artifact.source),
  ];
  return haystack.join(" ").toLowerCase().includes(query);
}

export function jobCounts(jobs: Job[]) {
  let active = 0;
  let completed = 0;
  let attention = 0;
  for (const job of jobs) {
    if (job.status === "queued" || job.status === "running") active += 1;
    if (job.status === "completed") completed += 1;
    if (["partial", "failed", "skipped", "needs_configuration"].includes(job.status)) attention += 1;
  }
  return { total: jobs.length, active, completed, attention };
}
