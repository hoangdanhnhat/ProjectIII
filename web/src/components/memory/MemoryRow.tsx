import type { Job } from "../../api/types";
import { bytes, duration, relative, shortHash, shortId, shortTime } from "../../lib/format";
import { memoryImage } from "../../lib/memory";
import { Icon } from "../ui/Icon";
import { StatusChip } from "../jobs/StatusChip";

interface MemoryRowProps {
  job: Job;
  onSelect: (job: Job) => void;
}

/** MemoryRow is one capture in the Memory view, reusing the collection grid. */
export function MemoryRow({ job, onSelect }: MemoryRowProps) {
  const image = memoryImage(job);
  return (
    <li className="job-item">
      <button
        type="button"
        className="job"
        onClick={() => onSelect(job)}
        aria-label={`Open memory capture ${job.id} for ${job.host_id}`}
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
            <span className="mono" title={image?.sha256 ?? ""}>
              {image ? shortHash(image.sha256) : "no image"}
            </span>
          </span>
        </span>
        <span className="job-artifacts">{image ? bytes(image.size) : "—"}</span>
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
