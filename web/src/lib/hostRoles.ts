import type { HostRole, HostRoleTier } from "../api/types";

/** Canonical role order, matching internal/hostrole's roleOrder. */
export const ROLE_ORDER: HostRole[] = [
  "domain_controller",
  "web_server",
  "workstation",
  "database_server",
  "mail_server",
  "dns_server",
  "dhcp_server",
];

export const ROLE_LABELS: Record<HostRole, string> = {
  domain_controller: "Domain controller",
  web_server: "Web server (IIS)",
  workstation: "Workstation",
  database_server: "Database server (MSSQL)",
  mail_server: "Mail server (Exchange)",
  dns_server: "DNS server",
  dhcp_server: "DHCP server",
};

export const TIER_LABELS: Record<HostRoleTier, string> = {
  confirmed: "Confirmed",
  probable: "Probable",
  possible: "Possible",
};

export const HOST_CLASS_LABELS: Record<string, string> = {
  domain_controller: "Domain controller",
  server: "Server",
  workstation: "Workstation",
  unknown: "Unknown host",
};

export function roleLabel(role: string): string {
  return ROLE_LABELS[role as HostRole] ?? role;
}

export function rolesLabel(roles: string[]): string {
  return roles.map(roleLabel).join(", ");
}
