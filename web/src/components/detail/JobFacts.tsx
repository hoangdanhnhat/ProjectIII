import type { Job } from "../../api/types";
import { absolute } from "../../lib/format";

export function JobFacts({ job }: { job: Job }) {
  return (
    <dl className="kv">
      <dt>Job ID</dt>
      <dd className="mono break">{job.id}</dd>
      <dt>Host</dt>
      <dd>{job.host_id || "—"}</dd>
      <dt>Scenario</dt>
      <dd>{job.scenario || "—"}</dd>
      <dt>Created</dt>
      <dd>{absolute(job.created_at)}</dd>
      <dt>Started</dt>
      <dd>{absolute(job.started_at)}</dd>
      <dt>Ended</dt>
      <dd>{absolute(job.ended_at)}</dd>
      {job.since ? (
        <>
          <dt>Modified since</dt>
          <dd>{absolute(job.since)}</dd>
        </>
      ) : null}
    </dl>
  );
}
