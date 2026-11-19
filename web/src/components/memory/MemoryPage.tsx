import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Job, Meta } from "../../api/types";
import { qk, useJobs } from "../../api/queries";
import { relative } from "../../lib/format";
import { isMemoryJob } from "../../lib/memory";
import { JobDetailSheet } from "../detail/JobDetailSheet";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { Skeleton } from "../ui/Skeleton";
import { MemoryCaptureDialog } from "./MemoryCaptureDialog";
import { MemoryRow } from "./MemoryRow";

interface MemoryPageProps {
  token: string;
  meta: Meta;
}

export function MemoryPage({ token, meta }: MemoryPageProps) {
  const jobsQuery = useJobs(token);
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const jobs = (jobsQuery.data?.jobs ?? [])
    .filter(isMemoryJob)
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
  const selected = jobs.find((job) => job.id === selectedId) ?? null;
  const updated = jobsQuery.dataUpdatedAt
    ? relative(new Date(jobsQuery.dataUpdatedAt).toISOString())
    : "—";

  // Seed the cache with the queued job so its sheet opens before the next poll.
  function handleCreated(job: Job) {
    queryClient.setQueryData<{ jobs: Job[] }>(qk.jobs(), (old) => ({
      jobs: [job, ...(old?.jobs ?? []).filter((item) => item.id !== job.id)],
    }));
    setDialogOpen(false);
    setSelectedId(job.id);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Forensics</div>
          <h1>Memory capture</h1>
          <p className="lede">
            {jobs.length === 0
              ? "No memory captures yet"
              : `${jobs.length} memory ${jobs.length === 1 ? "capture" : "captures"} · full physical RAM from the endpoint's acquisition tool`}
          </p>
        </div>
        <div className="page-actions">
          <span className="updated">Updated {updated}</span>
          <Button
            icon="refresh"
            busy={jobsQuery.isFetching}
            onClick={() => queryClient.invalidateQueries({ queryKey: qk.jobs() })}
          >
            Refresh
          </Button>
          <Button variant="primary" icon="plus" onClick={() => setDialogOpen(true)}>
            New memory capture
          </Button>
        </div>
      </div>

      <div className="callout" data-tone="amber">
        <span className="callout-label">Before you capture</span>
        <p>
          The agent runs the memory acquisition binary configured on the endpoint and needs an
          elevated account plus free disk equal to the machine&apos;s RAM. Without the memory flags
          the job returns <code className="mono">needs_configuration</code>. A capture can take
          minutes, and the resulting image may contain credentials and keys.
        </p>
      </div>

      {jobsQuery.error ? (
        <div className="banner" role="alert">
          Could not load memory captures: {jobsQuery.error.message}
        </div>
      ) : null}

      {jobsQuery.isLoading && jobs.length === 0 ? (
        <section className="panel">
          <div className="skeleton-stack" aria-hidden="true">
            <Skeleton />
            <Skeleton />
            <Skeleton />
          </div>
        </section>
      ) : jobs.length === 0 ? (
        <section className="panel">
          <EmptyState
            icon="server"
            title="No memory captures yet"
            description="Queue a capture to pull a full physical-memory image from a machine that runs the agent with a configured acquisition binary."
            action={
              <button type="button" className="btn btn--primary" onClick={() => setDialogOpen(true)}>
                New memory capture
              </button>
            }
          />
        </section>
      ) : (
        <section className="panel">
          <div className="job-head" aria-hidden="true">
            <span>Status</span>
            <span>Capture</span>
            <span>Image</span>
            <span>Created</span>
            <span>Duration</span>
            <span />
          </div>
          <ul className="job-list" aria-label="Memory captures">
            {jobs.map((job) => (
              <MemoryRow key={job.id} job={job} onSelect={(item) => setSelectedId(item.id)} />
            ))}
          </ul>
          <footer className="panel-foot">
            <span className="muted">{jobs.length} total</span>
          </footer>
        </section>
      )}

      {selected ? (
        <JobDetailSheet job={selected} token={token} onClose={() => setSelectedId(null)} />
      ) : null}

      <MemoryCaptureDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        token={token}
        defaultHost={meta.host_id}
        hosts={meta.hosts}
        onCreated={handleCreated}
      />
    </>
  );
}
