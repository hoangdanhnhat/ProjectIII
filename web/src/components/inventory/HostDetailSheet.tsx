import type { Host, HostRole } from "../../api/types";
import { useResetHostRoles, useSetHostRoles } from "../../api/queries";
import { absolute, relative } from "../../lib/format";
import { hostName, hostOSBuild, hostOSLabel } from "../../lib/hostFilters";
import { TIER_LABELS, roleLabel } from "../../lib/hostRoles";
import { Dialog } from "../ui/Dialog";
import { Icon } from "../ui/Icon";
import { Tag } from "../ui/Tag";
import { useToast } from "../ui/toast-context";
import { HostStatusChip } from "./HostStatusChip";
import { RoleEditor } from "./RoleEditor";

interface HostDetailSheetProps {
  host: Host;
  token: string;
  roleOptions: HostRole[];
  onClose: () => void;
}

export function HostDetailSheet({ host, token, roleOptions, onClose }: HostDetailSheetProps) {
  const setRoles = useSetHostRoles(token);
  const resetRoles = useResetHostRoles(token);
  const toast = useToast();

  async function apply(roles: HostRole[], note: string) {
    try {
      await setRoles.mutateAsync({ hostId: host.host_id, input: { roles, note } });
      toast("Manual roles saved — the agent will apply them on its next heartbeat.", "success");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not save the role override.", "error");
    }
  }

  async function reset() {
    try {
      await resetRoles.mutateAsync(host.host_id);
      toast("Role override cleared — the agent will resume automatic detection.");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not reset the role override.", "error");
    }
  }

  const pending = host.applied_role_revision < host.role_revision;

  return (
    <Dialog open onClose={onClose} labelledBy="host-title" className="sheet">
      <div className="sheet-inner">
        <header className="sheet-head">
          <div>
            <div className="eyebrow">Managed machine</div>
            <h2 id="host-title">{hostName(host)}</h2>
            <p className="sheet-sub mono">{host.host_id}</p>
          </div>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close details">
            <Icon name="x" />
          </button>
        </header>
        <div className="sheet-body">
          <div className="detail-statusline">
            <HostStatusChip status={host.status} />
            <Tag>{host.role_source === "manual" ? "Manual roles" : "Automatic roles"}</Tag>
            <span>
              Last seen {host.last_seen_at ? relative(host.last_seen_at) : "never"}
            </span>
          </div>

          <dl className="kv">
            <dt>Host ID</dt>
            <dd className="mono break">{host.host_id}</dd>
            <dt>Operating system</dt>
            <dd>
              {hostOSLabel(host)}
              {host.os.build ? ` · ${hostOSBuild(host)}` : ""}
            </dd>
            <dt>Host class</dt>
            <dd>{host.os.host_class || "unknown"}</dd>
            <dt>Agent version</dt>
            <dd>{host.agent_version || "—"}</dd>
            <dt>First seen</dt>
            <dd>{absolute(host.first_seen_at)}</dd>
            <dt>Last seen</dt>
            <dd>{absolute(host.last_seen_at)}</dd>
            <dt>Role checked</dt>
            <dd>{absolute(host.role_checked_at)}</dd>
          </dl>

          <section className="section">
            <div className="section-head">
              <h3>Effective roles</h3>
              <span className="count">{host.effective_roles.length}</span>
            </div>
            {host.effective_roles.length > 0 ? (
              <div className="role-tags">
                {host.effective_roles.map((role) => (
                  <Tag key={role}>{roleLabel(role)}</Tag>
                ))}
              </div>
            ) : (
              <div className="mini-empty">No server role is currently assigned to this machine.</div>
            )}
          </section>

          <section className="section">
            <div className="section-head">
              <h3>Automatic detection</h3>
              <span className="count">{host.auto_roles.length}</span>
            </div>
            {host.auto_roles.length > 0 ? (
              <div className="role-list">
                {host.auto_roles.map((role) => {
                  const percent = Math.round(role.confidence * 100);
                  return (
                    <article className="role-row" key={role.role}>
                      <div className="role-row-head">
                        <span className="role-name">{roleLabel(role.role)}</span>
                        <span className="tag">{TIER_LABELS[role.tier] ?? role.tier}</span>
                        <span className="role-confidence">{percent}%</span>
                      </div>
                      <div className="role-bar" aria-hidden="true">
                        <div className="role-bar-fill" style={{ width: `${percent}%` }} />
                      </div>
                    </article>
                  );
                })}
              </div>
            ) : (
              <div className="mini-empty">
                No automatic role has been detected yet
                {host.role_source === "manual" ? " (manual override is active)." : "."}
              </div>
            )}
            {host.role_error ? <p className="role-note">Detection error: {host.role_error}</p> : null}
            <p className="role-note">
              {!host.last_seen_at
                ? "No agent heartbeat yet."
                : pending
                  ? `Waiting for the agent to apply revision ${host.role_revision}.`
                  : `Agent applied revision ${host.role_revision}.`}
            </p>
          </section>

          <section className="section">
            <div className="section-head">
              <h3>Role assignment</h3>
            </div>
            {host.manual_note ? (
              <p className="role-note">
                Override note: {host.manual_note}
                {host.manual_updated_at ? ` · ${absolute(host.manual_updated_at)}` : ""}
              </p>
            ) : null}
            <RoleEditor
              key={`${host.host_id}-${host.role_revision}`}
              host={host}
              roleOptions={roleOptions}
              saving={setRoles.isPending}
              resetting={resetRoles.isPending}
              onApply={apply}
              onReset={reset}
            />
          </section>
        </div>
      </div>
    </Dialog>
  );
}
