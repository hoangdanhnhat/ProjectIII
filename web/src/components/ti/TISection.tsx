import { useMemo, useState } from "react";
import type { Artifact, Indicator, Job, Kind, Snapshot, TIReport } from "../../api/types";
import { useAddListEntry, useArtifactJSON, useRerunTI } from "../../api/queries";
import { Button } from "../ui/Button";
import { Icon } from "../ui/Icon";
import { useToast } from "../ui/toast-context";
import { ConnectionsTable } from "./ConnectionsTable";
import { DnsTable } from "./DnsTable";
import { FindingsTable } from "./FindingsTable";
import { TISummaryBar } from "./TISummaryBar";
import { TIStatusChip } from "./TIStatusChip";

type Tab = "findings" | "connections" | "dns";

const TABS: Array<{ id: Tab; label: string; icon: "check-circle" | "network" | "server" }> = [
  { id: "findings", label: "Findings", icon: "check-circle" },
  { id: "connections", label: "Connections", icon: "network" },
  { id: "dns", label: "DNS cache", icon: "server" },
];

function lastArtifact(job: Job, kind: Kind): Artifact | null {
  let found: Artifact | null = null;
  for (const artifact of job.artifacts ?? []) {
    if (artifact.kind === kind) found = artifact;
  }
  return found;
}

export function TISection({ job, token }: { job: Job; token: string }) {
  const snapshotArtifact = lastArtifact(job, "netstat_snapshot");
  const reportArtifact = lastArtifact(job, "ti_report");
  const snapshotQuery = useArtifactJSON<Snapshot>(token, job.id, snapshotArtifact?.id ?? null);
  const reportQuery = useArtifactJSON<TIReport>(token, job.id, reportArtifact?.id ?? null);
  const [tab, setTab] = useState<Tab>("findings");
  const [query, setQuery] = useState("");
  const toast = useToast();
  const addEntry = useAddListEntry(token);
  const rerun = useRerunTI(token);

  const snapshot = snapshotQuery.data ?? null;
  const report = reportQuery.data ?? null;
  const running = job.ti_status === "running";

  const flagged = useMemo(() => {
    const map = new Map<string, string>();
    for (const indicator of report?.indicators ?? []) {
      if (indicator.verdict === "blacklisted" || indicator.verdict === "malicious") {
        map.set(indicator.value, "red");
      } else if (indicator.verdict === "suspicious") {
        map.set(indicator.value, "amber");
      }
    }
    return map;
  }, [report]);

  async function listAndRerun(list: "whitelist" | "blacklist", indicator: Indicator) {
    const verb = list === "blacklist" ? "Blacklisted" : "Whitelisted";
    try {
      await addEntry.mutateAsync({
        list,
        value: indicator.value,
        note: `${list === "blacklist" ? "blacklisted" : "whitelisted"} from collection ${job.id}`,
      });
      toast(`${verb} ${indicator.value} — re-running the check.`, "success");
      await rerun.mutateAsync(job.id);
    } catch (err) {
      toast(err instanceof Error ? err.message : "Action failed.", "error");
    }
  }

  async function runAgain() {
    try {
      await rerun.mutateAsync(job.id);
      toast("Threat intel check re-queued.");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not re-run the check.", "error");
    }
  }

  const counts: Record<Tab, number> = {
    findings: report?.indicators.length ?? 0,
    connections: snapshot?.connections.length ?? 0,
    dns: snapshot?.dns_cache?.length ?? 0,
  };

  const findingsEmpty = reportArtifact
    ? reportQuery.isLoading
      ? "Loading report…"
      : "No indicators match this filter."
    : "No threat intel report yet — run a check to triage this collection.";

  const connectionsEmpty = !snapshotArtifact
    ? "No netstat snapshot was uploaded for this collection."
    : snapshotQuery.isLoading
      ? "Loading snapshot…"
      : "No connections match this filter.";

  const dnsEmpty = !snapshotArtifact
    ? "No netstat snapshot was uploaded for this collection."
    : snapshotQuery.isLoading
      ? "Loading snapshot…"
      : !snapshot?.dns_cache?.length
        ? "The DNS client cache was empty or unavailable on the endpoint."
        : "No DNS entries match this filter.";

  return (
    <section className="section ti">
      <div className="ti-head">
        <h3>Threat Intel</h3>
        {job.ti_status ? <TIStatusChip status={job.ti_status} /> : null}
        {snapshotArtifact ? (
          <Button
            small
            icon="refresh"
            busy={rerun.isPending}
            disabled={running}
            onClick={runAgain}
            title="Re-run the VirusTotal check with current settings and lists"
          >
            Re-run check
          </Button>
        ) : null}
      </div>

      {job.ti_reason ? <p className="ti-reason">{job.ti_reason}</p> : null}

      {running ? (
        <div className="ti-loading">
          <Icon name="loader" className="icon spin" />
          <span>Checking indicators on VirusTotal… this can take a few minutes at the free-tier rate limit.</span>
        </div>
      ) : null}

      {report?.summary ? <TISummaryBar summary={report.summary} /> : null}

      <div className="tabs" role="group" aria-label="Threat intel views">
        {TABS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            className={entry.id === tab ? "tab is-active" : "tab"}
            aria-pressed={entry.id === tab}
            onClick={() => setTab(entry.id)}
          >
            <Icon name={entry.icon} /> {entry.label} <span className="count">{counts[entry.id]}</span>
          </button>
        ))}
      </div>

      <div className="ti-tools">
        <div className="search">
          <Icon name="search" className="icon search-icon" />
          <input
            type="search"
            placeholder="Filter by IP, domain, process, verdict…"
            aria-label="Filter threat intel tables"
            value={query}
            onChange={(event) => setQuery(event.target.value.toLowerCase())}
            autoComplete="off"
          />
        </div>
      </div>

      {tab === "findings" ? (
        <FindingsTable
          indicators={report?.indicators ?? []}
          query={query}
          empty={findingsEmpty}
          onWhitelist={(indicator) => listAndRerun("whitelist", indicator)}
          onBlacklist={(indicator) => listAndRerun("blacklist", indicator)}
        />
      ) : tab === "connections" ? (
        <ConnectionsTable
          connections={snapshot?.connections ?? []}
          flagged={flagged}
          query={query}
          empty={connectionsEmpty}
        />
      ) : (
        <DnsTable records={snapshot?.dns_cache ?? []} flagged={flagged} query={query} empty={dnsEmpty} />
      )}
    </section>
  );
}
