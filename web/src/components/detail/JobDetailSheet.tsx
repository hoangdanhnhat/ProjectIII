import type { Job } from "../../api/types";
import { duration, relative } from "../../lib/format";
import { StatusChip } from "../jobs/StatusChip";
import { Icon } from "../ui/Icon";
import { Dialog } from "../ui/Dialog";
import { ArtifactList } from "./ArtifactList";
import { HostRoleCard } from "./HostRoleCard";
import { JobFacts } from "./JobFacts";
import { TISection } from "../ti/TISection";

interface JobDetailSheetProps {
  job: Job;
  token: string;
  onClose: () => void;
}

export function JobDetailSheet({ job, token, onClose }: JobDetailSheetProps) {
  const tone =
    job.status === "failed" || job.status === "partial"
      ? "amber"
      : job.status === "completed"
        ? "green"
        : "neutral";

  return (
    <Dialog open onClose={onClose} labelledBy="detail-title" className="sheet">
      <div className="sheet-inner">
        <header className="sheet-head">
          <div>
            <div className="eyebrow">Collection</div>
            <h2 id="detail-title">{job.host_id || "Collection"}</h2>
            <p className="sheet-sub mono">{job.id}</p>
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close details">
            <Icon name="x" />
          </button>
        </header>
        <div className="sheet-body">
          <div className="detail-statusline">
            <StatusChip status={job.status} />
            <span>Duration {duration(job)}</span>
            <span className="dot">·</span>
            <span>Created {relative(job.created_at)}</span>
          </div>

          {job.reason ? (
            <div className="callout" data-tone={tone}>
              <span className="callout-label">Result</span>
              <p>{job.reason}</p>
            </div>
          ) : null}

          <JobFacts job={job} />

          {job.scenario === "netstat.v1" ? <TISection job={job} token={token} /> : null}

          {job.scenario === "hostrole.v1" ? <HostRoleCard job={job} token={token} /> : null}

          <ArtifactList job={job} token={token} />
        </div>
      </div>
    </Dialog>
  );
}
