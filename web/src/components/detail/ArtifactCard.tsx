import type { Artifact, Job, Kind } from "../../api/types";
import { downloadArtifact } from "../../lib/download";
import { absolute, bytes, fileName, shortHash } from "../../lib/format";
import { useToast } from "../ui/toast-context";
import { Button } from "../ui/Button";
import { CopyButton } from "../ui/CopyButton";

const KIND_LABELS: Record<Kind, string> = {
  upload: "Upload",
  apache_log: "Apache log",
  iis_log: "IIS log",
  netstat_snapshot: "Netstat & DNS",
  event_log: "Event log",
  ti_report: "Threat Intel report",
  host_role: "Host role",
};

interface ArtifactCardProps {
  job: Job;
  artifact: Artifact;
  token: string;
}

export function ArtifactCard({ job, artifact, token }: ArtifactCardProps) {
  const toast = useToast();

  async function download() {
    try {
      await downloadArtifact(token, job.id, artifact.id, artifact.source);
      toast(`Downloaded ${fileName(artifact.source, artifact.id)}`, "success");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Download failed.", "error");
    }
  }

  return (
    <article className="artifact">
      <div className="artifact-top">
        <span className="tag">{KIND_LABELS[artifact.kind] ?? artifact.kind}</span>
        <span className="artifact-size">{bytes(artifact.size)}</span>
        <Button small icon="download" onClick={download}>
          Download
        </Button>
      </div>
      <div className="artifact-source mono break">{artifact.source || "—"}</div>
      <div className="artifact-meta">
        <span>Modified {absolute(artifact.modified_at)}</span>
        <span className="dot">·</span>
        <span>{artifact.mode || "—"}</span>
        <span className="dot">·</span>
        <span>Collected {absolute(artifact.collected_at)}</span>
      </div>
      <div className="hash-line">
        <span className="hash-label">SHA-256</span>
        <code className="mono" title={artifact.sha256}>
          {shortHash(artifact.sha256)}
        </code>
        <CopyButton value={artifact.sha256} label="SHA-256" />
      </div>
    </article>
  );
}
