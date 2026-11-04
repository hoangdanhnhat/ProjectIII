import type { Job } from "../../api/types";
import { duration, relative, shortId, shortTime } from "../../lib/format";
import { Icon } from "../ui/Icon";
import { StatusChip } from "./StatusChip";

interface JobRowProps {
  job: Job;
  onSelect: (job: Job) => void;
}

export function JobRow({ job, onSelect }: JobRowProps) {
  return (
    <li className="job-item">
      <button
        type="button"
        className="job"
        onClick={() => onSelect(job)}
        aria-label={`Open collection ${job.id} for ${job.host_id}`}
      >
        <span className="job-status">
          <StatusChip status={job.status} />
        </span>
        <span className="job-main">
          <span className="job-host">{job.host_id || "unknown host"}</span>
          <span className="job-meta">
            <code className="mono" title={job.id}>
              {shortId(job.id)}
            </code>
            <span className="dot">·</span>
            <span>{job.scenario}</span>
          </span>
        </span>
        <span className="job-artifacts">
          <strong>{job.artifacts.length}</strong> <span className="muted">artifacts</span>
        </span>
        <span className="job-time" title={job.created_at}>
          <span>{relative(job.created_at)}</span>
          <span className="job-time-abs">{shortTime(job.created_at)}</span>
        </span>
        <span className="job-duration">{duration(job)}</span>
        <Icon name="chevron-right" className="icon job-chevron" />
      </button>
    </li>
  );
}
