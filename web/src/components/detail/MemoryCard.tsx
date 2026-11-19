import type { Job, MemoryManifest } from "../../api/types";
import { useArtifactJSON } from "../../api/queries";
import { bytes, shortHash } from "../../lib/format";
import { formatMillis, lastMemoryArtifact, memoryImage } from "../../lib/memory";
import { CopyButton } from "../ui/CopyButton";

interface MemoryCardProps {
  job: Job;
  token: string;
}

/** MemoryCard summarizes the memory_manifest next to the image artifact. */
export function MemoryCard({ job, token }: MemoryCardProps) {
  const manifestArtifact = lastMemoryArtifact(job, "memory_manifest");
  const image = memoryImage(job);
  const query = useArtifactJSON<MemoryManifest>(token, job.id, manifestArtifact?.id ?? null);
  const manifest = query.data;
  const imageHash = manifest?.image?.sha256 ?? image?.sha256 ?? "";

  return (
    <section className="section">
      <div className="section-head">
        <h3>Capture manifest</h3>
        {image ? <span className="tag">{bytes(image.size)}</span> : null}
      </div>

      {!manifestArtifact ? (
        <div className="mini-empty">
          {job.status === "queued" || job.status === "running"
            ? "Waiting for the agent to upload the capture manifest…"
            : "No capture manifest was uploaded for this job."}
        </div>
      ) : query.isLoading ? (
        <div className="mini-empty">Loading the capture manifest…</div>
      ) : !manifest ? (
        <div className="mini-empty">The capture manifest could not be read.</div>
      ) : (
        <>
          <dl className="kv">
            <dt>Image</dt>
            <dd>
              {manifest.image ? `${bytes(manifest.image.size)} · ` : ""}
              {imageHash ? (
                <>
                  <code className="mono" title={imageHash}>
                    {shortHash(imageHash)}
                  </code>{" "}
                  <CopyButton value={imageHash} label="image SHA-256" />
                </>
              ) : (
                "not captured"
              )}
            </dd>
            <dt>Result</dt>
            <dd>
              {manifest.result.status === "completed" ? "Completed" : "Failed"} · exit code{" "}
              {manifest.result.exit_code}
            </dd>
            <dt>Tool</dt>
            <dd>
              {manifest.tool.name}
              {manifest.tool.version ? ` ${manifest.tool.version}` : ""}
            </dd>
            <dt>Tool SHA-256</dt>
            <dd>
              <code className="mono" title={manifest.tool.sha256}>
                {shortHash(manifest.tool.sha256)}
              </code>{" "}
              <CopyButton value={manifest.tool.sha256} label="tool SHA-256" />
            </dd>
            <dt>Physical RAM</dt>
            <dd>{bytes(manifest.memory_total_bytes)}</dd>
            <dt>Acquisition</dt>
            <dd>{formatMillis(manifest.duration_ms)}</dd>
          </dl>

          {manifest.result.status === "failed" ? (
            <div className="callout" data-tone="amber">
              <span className="callout-label">Tool failure</span>
              <p>{manifest.result.error || "The acquisition tool reported a failure."}</p>
              {manifest.result.stderr_tail ? (
                <pre className="memory-log">{manifest.result.stderr_tail}</pre>
              ) : null}
            </div>
          ) : null}

          {manifest.notes.length > 0 ? (
            <ul className="memory-notes">
              {manifest.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}

          {manifest.result.stdout_tail ? (
            <details className="role-evidence">
              <summary>Tool output</summary>
              <pre className="memory-log">{manifest.result.stdout_tail}</pre>
            </details>
          ) : null}
        </>
      )}
    </section>
  );
}
