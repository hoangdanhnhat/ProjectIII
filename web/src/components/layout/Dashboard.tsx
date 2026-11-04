import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Job, Meta } from "../../api/types";
import { qk } from "../../api/queries";
import { useJobs } from "../../api/queries";
import { jobCounts, type FilterId } from "../../lib/jobFilters";
import { relative } from "../../lib/format";
import { Button } from "../ui/Button";
import { JobDetailSheet } from "../detail/JobDetailSheet";
import { JobList } from "../jobs/JobList";
import { NewJobDialog } from "../jobs/NewJobDialog";
import { StatsGrid } from "../jobs/StatsGrid";

interface DashboardProps {
  token: string;
  meta: Meta;
}

export function Dashboard({ token, meta }: DashboardProps) {
  const jobsQuery = useJobs(token);
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<FilterId>("all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [newOpen, setNewOpen] = useState(false);

  const jobs = jobsQuery.data?.jobs ?? [];
  const selected = jobs.find((job) => job.id === selectedId) ?? null;
  const updated = jobsQuery.dataUpdatedAt
    ? relative(new Date(jobsQuery.dataUpdatedAt).toISOString())
    : "—";

  function handleCreated(job: Job) {
    setNewOpen(false);
    setSelectedId(job.id);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Operations</div>
          <h1>Collections</h1>
          <p className="lede">
            Host {meta.host_id} · {meta.scenarios.join(", ")}
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
          <Button variant="primary" icon="plus" onClick={() => setNewOpen(true)}>
            New collection
          </Button>
        </div>
      </div>

      <StatsGrid counts={jobCounts(jobs)} />

      {jobsQuery.error ? (
        <div className="banner" role="alert">
          Could not load collections: {jobsQuery.error.message}
        </div>
      ) : null}

      <JobList
        jobs={jobs}
        loading={jobsQuery.isLoading}
        filter={filter}
        query={query}
        onFilterChange={setFilter}
        onQueryChange={setQuery}
        onSelect={(job) => setSelectedId(job.id)}
        onNew={() => setNewOpen(true)}
      />

      {selected ? (
        <JobDetailSheet job={selected} token={token} onClose={() => setSelectedId(null)} />
      ) : null}

      <NewJobDialog
        open={newOpen}
        onClose={() => setNewOpen(false)}
        token={token}
        defaultHost={meta.host_id}
        scenarios={meta.scenarios}
        onCreated={handleCreated}
      />
    </>
  );
}
