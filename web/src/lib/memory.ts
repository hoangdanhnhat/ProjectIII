import type { Artifact, Job } from "../api/types";

/** The catalog scenario ID for full physical-memory capture. */
export const MEMORY_SCENARIO = "memory.v1";

export function isMemoryJob(job: Job): boolean {
  return job.scenario === MEMORY_SCENARIO;
}

/** lastMemoryArtifact returns the last artifact of a memory kind in a job. */
export function lastMemoryArtifact(job: Job, kind: "memory_image" | "memory_manifest"): Artifact | null {
  let found: Artifact | null = null;
  for (const artifact of job.artifacts ?? []) {
    if (artifact.kind === kind) found = artifact;
  }
  return found;
}

/** memoryImage returns the captured image artifact, if the job produced one. */
export function memoryImage(job: Job): Artifact | null {
  return lastMemoryArtifact(job, "memory_image");
}

/** formatMillis renders an acquisition duration from milliseconds. */
export function formatMillis(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}
