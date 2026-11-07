import type { Host } from "../../api/types";
import { relative } from "../../lib/format";
import { hostName, hostOSBuild, hostOSLabel } from "../../lib/hostFilters";
import { roleLabel } from "../../lib/hostRoles";
import { Icon } from "../ui/Icon";
import { Tag } from "../ui/Tag";
import { HostStatusChip } from "./HostStatusChip";

export function HostRow({ host, onSelect }: { host: Host; onSelect: (host: Host) => void }) {
  const roles = host.effective_roles ?? [];
  return (
    <li className="host-item">
      <button
        type="button"
        className="host-row"
        onClick={() => onSelect(host)}
        aria-label={`Open machine ${hostName(host)}`}
      >
        <span className="host-main">
          <span className="host-name">{hostName(host)}</span>
          <span className="host-meta">
            <code className="mono">{host.host_id}</code>
            <span className="dot">·</span>
            <span>{hostOSLabel(host)}</span>
            {host.os.build ? (
              <>
                <span className="dot">·</span>
                <span>{hostOSBuild(host)}</span>
              </>
            ) : null}
          </span>
        </span>
        <span className="host-roles">
          {roles.length > 0 ? (
            roles.map((role) => <Tag key={role}>{roleLabel(role)}</Tag>)
          ) : (
            <span className="muted">No role detected</span>
          )}
        </span>
        <span className="host-source">
          <Tag>{host.role_source === "manual" ? "Manual" : "Automatic"}</Tag>
        </span>
        <span className="host-seen" title={host.last_seen_at ?? undefined}>
          {host.last_seen_at ? relative(host.last_seen_at) : "Never seen"}
        </span>
        <span className="host-status">
          <HostStatusChip status={host.status} />
        </span>
        <Icon name="chevron-right" className="icon host-chevron" />
      </button>
    </li>
  );
}
