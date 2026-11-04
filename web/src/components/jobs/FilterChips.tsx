import type { Job } from "../../api/types";
import { FILTERS, type FilterId } from "../../lib/jobFilters";

interface FilterChipsProps {
  jobs: Job[];
  active: FilterId;
  onChange: (id: FilterId) => void;
}

export function FilterChips({ jobs, active, onChange }: FilterChipsProps) {
  return (
    <div className="filters" role="group" aria-label="Filter by status">
      {FILTERS.map((filter) => {
        const count = jobs.filter(filter.match).length;
        const isActive = filter.id === active;
        return (
          <button
            key={filter.id}
            type="button"
            className={isActive ? "chip-filter is-active" : "chip-filter"}
            onClick={() => onChange(filter.id)}
            aria-pressed={isActive}
          >
            {filter.label}
            <span className="count">{count}</span>
          </button>
        );
      })}
    </div>
  );
}
