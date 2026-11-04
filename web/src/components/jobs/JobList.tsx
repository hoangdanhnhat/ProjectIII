import type { Job } from "../../api/types";
import type { FilterId } from "../../lib/jobFilters";
import { FILTERS, matchesQuery } from "../../lib/jobFilters";
import { EmptyState } from "../ui/EmptyState";
import { Icon } from "../ui/Icon";
import { Skeleton } from "../ui/Skeleton";
import { FilterChips } from "./FilterChips";
import { JobRow } from "./JobRow";

interface JobListProps {
  jobs: Job[];
  loading: boolean;
  filter: FilterId;
  query: string;
  onFilterChange: (id: FilterId) => void;
  onQueryChange: (value: string) => void;
  onSelect: (job: Job) => void;
  onNew: () => void;
}

export function JobList({
  jobs,
  loading,
  filter,
  query,
  onFilterChange,
  onQueryChange,
  onSelect,
  onNew,
}: JobListProps) {
  const matcher = FILTERS.find((item) => item.id === filter)?.match ?? (() => true);
  const visible = jobs.filter(matcher).filter((job) => matchesQuery(job, query));
  const hasJobs = jobs.length > 0;

  return (
    <section className="panel">
      <div className="panel-head">
        <div className="search">
          <Icon name="search" className="icon search-icon" />
          <input
            type="search"
            placeholder="Filter by host, job ID, reason…"
            aria-label="Filter collections"
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            autoComplete="off"
          />
        </div>
        <FilterChips jobs={jobs} active={filter} onChange={onFilterChange} />
      </div>

      {visible.length > 0 ? (
        <>
          <div className="job-head" aria-hidden="true">
            <span>Status</span>
            <span>Collection</span>
            <span>Artifacts</span>
            <span>Created</span>
            <span>Duration</span>
            <span />
          </div>
          <ul className="job-list" aria-label="Collections">
            {visible.map((job) => (
              <JobRow key={job.id} job={job} onSelect={onSelect} />
            ))}
          </ul>
        </>
      ) : null}

      {loading && !hasJobs ? (
        <div className="skeleton-stack" aria-hidden="true">
          <Skeleton />
          <Skeleton />
          <Skeleton />
        </div>
      ) : null}

      {!loading && visible.length === 0 ? (
        <EmptyState
          title={hasJobs ? "No matching collections" : "No collections yet"}
          description={
            hasJobs
              ? "Adjust the search text or status filter."
              : "Queue a collection to pull evidence from the registered host."
          }
          action={
            hasJobs ? undefined : (
              <button type="button" className="btn btn--primary" onClick={onNew}>
                <Icon name="plus" /> New collection
              </button>
            )
          }
        />
      ) : null}

      <footer className="panel-foot">
        <span className="muted">
          {visible.length === jobs.length
            ? `${jobs.length} total`
            : `${visible.length} of ${jobs.length}`}
        </span>
      </footer>
    </section>
  );
}
