import type { Host } from "../../api/types";
import type { HostFilterState } from "../../lib/hostFilters";
import { EmptyState } from "../ui/EmptyState";
import { Skeleton } from "../ui/Skeleton";
import { HostFilters as HostFilterControls } from "./HostFilters";
import { HostRow } from "./HostRow";

interface HostListProps {
  hosts: Host[];
  total: number;
  loading: boolean;
  filters: HostFilterState;
  osOptions: string[];
  classOptions: string[];
  onFiltersChange: (filters: HostFilterState) => void;
  onSelect: (host: Host) => void;
}

export function HostList({
  hosts,
  total,
  loading,
  filters,
  osOptions,
  classOptions,
  onFiltersChange,
  onSelect,
}: HostListProps) {
  return (
    <section className="panel host-panel">
      <div className="panel-head host-panel-head">
        <HostFilterControls
          filters={filters}
          osOptions={osOptions}
          classOptions={classOptions}
          onChange={onFiltersChange}
        />
      </div>

      {hosts.length > 0 ? (
        <>
          <div className="host-head" aria-hidden="true">
            <span>Machine</span>
            <span>Roles</span>
            <span>Source</span>
            <span>Last seen</span>
            <span>Status</span>
            <span />
          </div>
          <ul className="host-list" aria-label="Managed machines">
            {hosts.map((host) => (
              <HostRow key={host.host_id} host={host} onSelect={onSelect} />
            ))}
          </ul>
        </>
      ) : null}

      {loading && total === 0 ? (
        <div className="skeleton-stack" aria-hidden="true">
          <Skeleton />
          <Skeleton />
          <Skeleton />
        </div>
      ) : null}

      {!loading && hosts.length === 0 ? (
        <EmptyState
          icon="server"
          title={total > 0 ? "No matching machines" : "No machines yet"}
          description={
            total > 0
              ? "Adjust the search text or filters."
              : "Machines appear here after an agent heartbeats to the server."
          }
        />
      ) : null}

      <footer className="panel-foot">
        <span className="muted">
          {hosts.length === total ? `${total} total` : `${hosts.length} of ${total}`}
        </span>
      </footer>
    </section>
  );
}
