import { useState } from "react";
import type {
  Artifact,
  Job,
  VolatilityPluginResult,
  VolatilityReport,
  VolatilityStatus,
} from "../../api/types";
import { useArtifactJSON, useRunVolatility } from "../../api/queries";
import { bytes } from "../../lib/format";
import { formatMillis } from "../../lib/memory";
import { Button } from "../ui/Button";
import { Chip, type Tone } from "../ui/Chip";
import { useToast } from "../ui/toast-context";
import { PluginTableDialog } from "./PluginTableDialog";

const STATUS: Record<VolatilityStatus, { label: string; tone: Tone }> = {
  running: { label: "Running", tone: "blue" },
  completed: { label: "Completed", tone: "green" },
  partial: { label: "Partial", tone: "amber" },
  failed: { label: "Failed", tone: "red" },
  skipped: { label: "Skipped", tone: "neutral" },
  interrupted: { label: "Interrupted", tone: "neutral" },
};

function lastArtifact(job: Job, kind: "volatility_report"): Artifact | null {
  let found: Artifact | null = null;
  for (const artifact of job.artifacts ?? []) {
    if (artifact.kind === kind) found = artifact;
  }
  return found;
}

interface MemoryAnalysisCardProps {
  job: Job;
  token: string;
}

/** MemoryAnalysisCard summarizes the server-side Volatility 3 analysis. */
export function MemoryAnalysisCard({ job, token }: MemoryAnalysisCardProps) {
  const reportArtifact = lastArtifact(job, "volatility_report");
  const query = useArtifactJSON<VolatilityReport>(token, job.id, reportArtifact?.id ?? null);
  const run = useRunVolatility(token);
  const toast = useToast();
  const [viewing, setViewing] = useState<VolatilityPluginResult | null>(null);
  const status = (job.volatility_status ?? "") as VolatilityStatus | "";
  const statusInfo = status
    ? (STATUS[status] ?? { label: status, tone: "neutral" as Tone })
    : null;
  const report = query.data;
  const reason = job.volatility_reason ?? "";
  const kernelHint = /kernel layer|translation layer|unable to validate/i.test(reason);

  async function rerun() {
    try {
      await run.mutateAsync(job.id);
      toast("Memory analysis queued.", "success");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not start memory analysis.", "error");
    }
  }

  const canRerun =
    (job.status === "completed" || job.status === "partial") &&
    status !== "running" &&
    !run.isPending;

  return (
    <section className="section">
      <div className="section-head">
        <h3>Memory analysis</h3>
        <div className="analysis-actions">
          {statusInfo ? (
            <Chip tone={statusInfo.tone} title="Volatility 3 analysis">
              {statusInfo.label}
            </Chip>
          ) : null}
          <Button small icon="refresh" busy={run.isPending} disabled={!canRerun} onClick={rerun}>
            {status === "running" ? "Analyzing…" : "Re-run analysis"}
          </Button>
        </div>
      </div>

      {status === "running" ? (
        <div className="mini-empty">Volatility is analyzing the memory image…</div>
      ) : null}

      {!reportArtifact && status !== "running" ? (
        <div className="mini-empty">
          {reason
            ? reason
            : "No analysis results yet. Completed memory captures are analyzed automatically when Volatility is configured on the server."}
        </div>
      ) : null}

      {reportArtifact && query.isLoading ? (
        <div className="mini-empty">Loading the analysis report…</div>
      ) : null}

      {reportArtifact && !query.isLoading && !report ? (
        <div className="mini-empty">The analysis report could not be read.</div>
      ) : null}

      {report ? (
        <>
          <p className="analysis-summary">
            {report.summary.completed}/{report.summary.requested} plugins ·{" "}
            {report.summary.rows} rows · Volatility {report.engine.version}
          </p>
          {reason && status !== "completed" ? <p className="ti-reason">{reason}</p> : null}
          {kernelHint ? (
            <div className="callout" data-tone="amber">
              <span className="callout-label">Image not analyzable</span>
              <p>
                Volatility could not find a Windows kernel layer. The image may have been captured
                with a broken acquisition mode; capture it again with{" "}
                <code className="mono">winpmem-physical</code> (<code className="mono">-1</code>).
              </p>
            </div>
          ) : null}

          <div className="table-wrap">
            <table className="table" aria-label="Volatility plugin results">
              <thead>
                <tr>
                  <th>Plugin</th>
                  <th>Status</th>
                  <th className="num">Rows</th>
                  <th className="num">Time</th>
                  <th className="num">Size</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {report.plugins.map((plugin) => (
                  <tr
                    key={plugin.name}
                    data-tone={plugin.status === "completed" ? undefined : "amber"}
                  >
                    <td>
                      <div className="cell-main">
                        <code className="mono strong">{plugin.name}</code>
                      </div>
                      {plugin.error ? <div className="cell-sub">{plugin.error}</div> : null}
                    </td>
                    <td>{plugin.status}</td>
                    <td className="num">{plugin.rows}</td>
                    <td className="num">{formatMillis(plugin.duration_ms)}</td>
                    <td className="num">{bytes(plugin.size)}</td>
                    <td>
                      {plugin.artifact_id ? (
                        <Button small onClick={() => setViewing(plugin)}>
                          View
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {report.notes.length > 0 ? (
            <details className="role-evidence">
              <summary>Analysis notes</summary>
              <ul className="memory-notes">
                {report.notes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </details>
          ) : null}
        </>
      ) : null}

      {viewing ? (
        <PluginTableDialog
          jobId={job.id}
          token={token}
          plugin={viewing}
          onClose={() => setViewing(null)}
        />
      ) : null}
    </section>
  );
}
