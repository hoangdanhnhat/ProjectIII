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
  memory_image: "Memory image",
  memory_manifest: "Memory manifest",
  volatility_report: "Analysis report",
  volatility_plugin: "Plugin output",
};

// Browsers buffer a blob in memory before saving it; images above this size
// are fetched with curl instead, which streams straight to disk.
const MAX_BLOB_DOWNLOAD = 512 * 1024 * 1024;

function curlCommand(jobId: string, artifactId: string, source: string): string {
  const base = window.location.origin;
  return `curl -fsS -H "Authorization: Bearer $DFIR_OPERATOR_TOKEN" -o ${fileName(source, artifactId)} ${base}/v1/jobs/${jobId}/artifacts/${artifactId}`;
}

interface ArtifactCardProps {
  job: Job;
  artifact: Artifact;
  token: string;
}

export function ArtifactCard({ job, artifact, token }: ArtifactCardProps) {
  const toast = useToast();
  const large = artifact.size > MAX_BLOB_DOWNLOAD;
  const command = curlCommand(job.id, artifact.id, artifact.source);

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
        {large ? (
          <span className="artifact-size">too large for the browser</span>
        ) : (
          <Button small icon="download" onClick={download}>
            Download
          </Button>
        )}
      </div>
      <div className="artifact-source mono break">{artifact.source || "—"}</div>
      {large && (
        <div className="artifact-hint">
          <span>Retrieve with curl:</span>
          <code className="mono break">{command}</code>
          <CopyButton value={command} label="curl command" />
        </div>
      )}
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
