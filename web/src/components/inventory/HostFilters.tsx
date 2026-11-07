import type { HostRole } from "../../api/types";
import { HOST_CLASS_LABELS, ROLE_LABELS, ROLE_ORDER } from "../../lib/hostRoles";
import type { HostFilterState } from "../../lib/hostFilters";
import { Icon } from "../ui/Icon";

interface HostFiltersProps {
  filters: HostFilterState;
  osOptions: string[];
  classOptions: string[];
  onChange: (next: HostFilterState) => void;
}

export function HostFilters({ filters, osOptions, classOptions, onChange }: HostFiltersProps) {
  const active =
    filters.query !== "" ||
    filters.roles.length > 0 ||
    filters.os !== "" ||
    filters.hostClass !== "" ||
    filters.source !== "" ||
    filters.status !== "";

  function toggleRole(role: HostRole) {
    const roles = filters.roles.includes(role)
      ? filters.roles.filter((entry) => entry !== role)
      : [...filters.roles, role];
    onChange({ ...filters, roles });
  }

  return (
    <div className="host-tools">
      <div className="search">
        <Icon name="search" className="icon search-icon" />
        <input
          type="search"
          placeholder="Filter by hostname, OS, role…"
          aria-label="Filter machines"
          value={filters.query}
          onChange={(event) => onChange({ ...filters, query: event.target.value })}
          autoComplete="off"
        />
      </div>
      <div className="filters" role="group" aria-label="Filter by role">
        {ROLE_ORDER.map((role) => (
          <button
            key={role}
            type="button"
            className={filters.roles.includes(role) ? "chip-filter is-active" : "chip-filter"}
            aria-pressed={filters.roles.includes(role)}
            onClick={() => toggleRole(role)}
          >
            {ROLE_LABELS[role]}
          </button>
        ))}
      </div>
      <div className="host-selects">
        <select
          className="filter-select"
          aria-label="Filter by OS"
          value={filters.os}
          onChange={(event) => onChange({ ...filters, os: event.target.value })}
        >
          <option value="">All operating systems</option>
          {osOptions.map((os) => (
            <option key={os} value={os}>
              {os}
            </option>
          ))}
        </select>
        <select
          className="filter-select"
          aria-label="Filter by host class"
          value={filters.hostClass}
          onChange={(event) => onChange({ ...filters, hostClass: event.target.value })}
        >
          <option value="">All host classes</option>
          {classOptions.map((value) => (
            <option key={value} value={value}>
              {HOST_CLASS_LABELS[value] ?? value}
            </option>
          ))}
        </select>
        <select
          className="filter-select"
          aria-label="Filter by role source"
          value={filters.source}
          onChange={(event) => onChange({ ...filters, source: event.target.value })}
        >
          <option value="">All sources</option>
          <option value="auto">Automatic</option>
          <option value="manual">Manual</option>
        </select>
        <select
          className="filter-select"
          aria-label="Filter by status"
          value={filters.status}
          onChange={(event) => onChange({ ...filters, status: event.target.value })}
        >
          <option value="">All statuses</option>
          <option value="online">Online</option>
          <option value="stale">Stale</option>
          <option value="offline">Offline</option>
          <option value="never_seen">Never seen</option>
        </select>
        {active ? (
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={() =>
              onChange({ query: "", roles: [], os: "", hostClass: "", source: "", status: "" })
            }
          >
            Clear
          </button>
        ) : null}
      </div>
    </div>
  );
}
