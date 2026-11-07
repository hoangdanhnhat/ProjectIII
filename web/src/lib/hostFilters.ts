import type { Host, HostRole } from "../api/types";
import { roleLabel } from "./hostRoles";

export interface HostFilterState {
  query: string;
  roles: HostRole[];
  os: string;
  hostClass: string;
  source: string;
  status: string;
}

export const EMPTY_HOST_FILTERS: HostFilterState = {
  query: "",
  roles: [],
  os: "",
  hostClass: "",
  source: "",
  status: "",
};

export function hostName(host: Host): string {
  return host.hostname || host.host_id;
}

export function hostOSLabel(host: Host): string {
  const name = host.os.name?.trim();
  if (name) return name;
  const platform = host.os.platform?.trim();
  return platform ? platform : "Unknown OS";
}

export function hostClass(host: Host): string {
  return host.os.host_class?.trim() || "unknown";
}

export function hostOSBuild(host: Host): string {
  if (!host.os.build) return "";
  return `build ${host.os.build}`;
}

export function matchesHost(host: Host, filters: HostFilterState): boolean {
  if (filters.roles.length > 0) {
    const effective = new Set(host.effective_roles ?? []);
    if (!filters.roles.some((role) => effective.has(role))) return false;
  }
  if (filters.os && hostOSLabel(host) !== filters.os) return false;
  if (filters.hostClass && hostClass(host) !== filters.hostClass) return false;
  if (filters.source && host.role_source !== filters.source) return false;
  if (filters.status && host.status !== filters.status) return false;
  if (!filters.query) return true;
  const haystack = [
    host.host_id,
    host.hostname ?? "",
    hostOSLabel(host),
    host.os.build ?? "",
    host.os.product_type ?? "",
    hostClass(host),
    host.role_source,
    host.status,
    host.agent_version ?? "",
    ...(host.effective_roles ?? []).map(roleLabel),
    ...(host.auto_roles ?? []).map((role) => roleLabel(role.role)),
  ];
  return haystack.join(" ").toLowerCase().includes(filters.query.toLowerCase());
}

export function distinctOS(hosts: Host[]): string[] {
  const values = new Set<string>();
  for (const host of hosts) values.add(hostOSLabel(host));
  return [...values].sort((a, b) => a.localeCompare(b));
}

export function distinctHostClasses(hosts: Host[]): string[] {
  const values = new Set<string>();
  for (const host of hosts) values.add(hostClass(host));
  return [...values].sort((a, b) => a.localeCompare(b));
}
