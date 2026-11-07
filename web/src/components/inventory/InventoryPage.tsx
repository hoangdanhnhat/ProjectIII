import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Host, HostRole, Meta } from "../../api/types";
import { qk, useHosts } from "../../api/queries";
import { relative } from "../../lib/format";
import {
  EMPTY_HOST_FILTERS,
  distinctHostClasses,
  distinctOS,
  hostName,
  matchesHost,
  type HostFilterState,
} from "../../lib/hostFilters";
import { ROLE_ORDER } from "../../lib/hostRoles";
import { Button } from "../ui/Button";
import { HostDetailSheet } from "./HostDetailSheet";
import { HostList } from "./HostList";
import { InventoryStats } from "./InventoryStats";

const STATUS_ORDER: Record<string, number> = {
  online: 0,
  stale: 1,
  never_seen: 2,
  offline: 3,
};

function sortHosts(hosts: Host[]): Host[] {
  return [...hosts].sort((a, b) => {
    const status = (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9);
    if (status !== 0) return status;
    return hostName(a).localeCompare(hostName(b));
  });
}

export function InventoryPage({ token, meta }: { token: string; meta: Meta }) {
  const hostsQuery = useHosts(token);
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<HostFilterState>(EMPTY_HOST_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const hosts = hostsQuery.data?.hosts ?? [];
  const visible = sortHosts(hosts.filter((host) => matchesHost(host, filters)));
  const selected = hosts.find((host) => host.host_id === selectedId) ?? null;
  const roleOptions: HostRole[] = meta.roles?.length ? meta.roles : ROLE_ORDER;
  const updated = hostsQuery.dataUpdatedAt
    ? relative(new Date(hostsQuery.dataUpdatedAt).toISOString())
    : "—";

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Operations</div>
          <h1>Machines</h1>
          <p className="lede">
            {hosts.length} managed {hosts.length === 1 ? "machine" : "machines"} · automatic role
            detection with operator overrides
          </p>
        </div>
        <div className="page-actions">
          <span className="updated">Updated {updated}</span>
          <Button
            icon="refresh"
            busy={hostsQuery.isFetching}
            onClick={() => queryClient.invalidateQueries({ queryKey: qk.hosts() })}
          >
            Refresh
          </Button>
        </div>
      </div>

      <InventoryStats hosts={hosts} />

      {hostsQuery.error ? (
        <div className="banner" role="alert">
          Could not load machines: {hostsQuery.error.message}
        </div>
      ) : null}

      <HostList
        hosts={visible}
        total={hosts.length}
        loading={hostsQuery.isLoading}
        filters={filters}
        osOptions={distinctOS(hosts)}
        classOptions={distinctHostClasses(hosts)}
        onFiltersChange={setFilters}
        onSelect={(host) => setSelectedId(host.host_id)}
      />

      {selected ? (
        <HostDetailSheet
          host={selected}
          token={token}
          roleOptions={roleOptions}
          onClose={() => setSelectedId(null)}
        />
      ) : null}
    </>
  );
}
