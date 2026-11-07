import type { Artifact, HostRole, HostRoleProfile, Job, Kind } from "../../api/types";
import { useArtifactJSON } from "../../api/queries";

const ROLE_LABELS: Record<HostRole, string> = {
  domain_controller: "Domain controller",
  web_server: "Web server (IIS)",
  file_server: "File server (SMB)",
  database_server: "Database server (MSSQL)",
  mail_server: "Mail server (Exchange)",
  dns_server: "DNS server",
  dhcp_server: "DHCP server",
};

const TIER_LABELS: Record<HostRoleProfile["roles"][number]["tier"], string> = {
  confirmed: "Confirmed",
  probable: "Probable",
  possible: "Possible",
};

const HOST_CLASS_LABELS: Record<HostRoleProfile["host"]["host_class"], string> = {
  domain_controller: "domain controller",
  server: "server",
  workstation: "workstation",
  unknown: "host",
};

function lastArtifact(job: Job, kind: Kind): Artifact | null {
  let found: Artifact | null = null;
  for (const artifact of job.artifacts ?? []) {
    if (artifact.kind === kind) found = artifact;
  }
  return found;
}

function hostSummary(profile: HostRoleProfile, fallback: string): string {
  const host = profile.host;
  const parts = [host.hostname || fallback || "Unknown host"];
  if (host.os_name) parts.push(host.os_name);
  if (host.os_build) parts.push(`build ${host.os_build}`);
  parts.push(HOST_CLASS_LABELS[host.host_class] ?? host.host_class);
  return parts.join(" · ");
}

export function HostRoleCard({ job, token }: { job: Job; token: string }) {
  const artifact = lastArtifact(job, "host_role");
  const query = useArtifactJSON<HostRoleProfile>(token, job.id, artifact?.id ?? null);
  if (!artifact) return null;

  const profile = query.data;
  return (
    <section className="section role">
      <div className="section-head">
        <h3>Host role</h3>
        {profile?.primary_role ? (
          <span className="tag">{ROLE_LABELS[profile.primary_role] ?? profile.primary_role}</span>
        ) : null}
      </div>

      {query.isLoading ? (
        <div className="mini-empty">Loading the role profile…</div>
      ) : !profile ? (
        <div className="mini-empty">The role profile could not be read.</div>
      ) : (
        <>
          <p className="role-host">{hostSummary(profile, job.host_id)}</p>
          {profile.roles.length === 0 ? (
            <div className="mini-empty">
              No server role was detected — this looks like a{" "}
              {HOST_CLASS_LABELS[profile.host.host_class] ?? "host"}.
            </div>
          ) : (
            <div className="role-list">
              {profile.roles.map((result) => {
                const percent = Math.round(result.confidence * 100);
                return (
                  <article className="role-row" key={result.role}>
                    <div className="role-row-head">
                      <span className="role-name">{ROLE_LABELS[result.role] ?? result.role}</span>
                      <span className="tag">{TIER_LABELS[result.tier] ?? result.tier}</span>
                      <span className="role-confidence">{percent}%</span>
                    </div>
                    <div className="role-bar" aria-hidden="true">
                      <div className="role-bar-fill" style={{ width: `${percent}%` }} />
                    </div>
                    {result.evidence.length > 0 ? (
                      <details className="role-evidence">
                        <summary>
                          {result.evidence.length} evidence item
                          {result.evidence.length === 1 ? "" : "s"}
                        </summary>
                        <ul className="role-evidence-list">
                          {result.evidence.map((item, index) => (
                            <li key={`${item.source}-${index}`}>
                              <span className="role-evidence-source">{item.source}</span> — {item.detail}{" "}
                              <span className="role-note">({item.strength})</span>
                            </li>
                          ))}
                        </ul>
                      </details>
                    ) : null}
                  </article>
                );
              })}
            </div>
          )}

          {profile.probe_errors?.length ? (
            <details className="role-evidence">
              <summary>
                {profile.probe_errors.length} probe error
                {profile.probe_errors.length === 1 ? "" : "s"} — some evidence could not be read
              </summary>
              <ul className="role-evidence-list">
                {profile.probe_errors.map((item, index) => (
                  <li key={`${item.source}-${index}`}>
                    <span className="role-evidence-source">{item.source}</span> — {item.detail}
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
        </>
      )}
    </section>
  );
}
