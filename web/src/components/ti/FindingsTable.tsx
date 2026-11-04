import type { Indicator } from "../../api/types";
import { Icon } from "../ui/Icon";
import { Tag } from "../ui/Tag";
import { VerdictChip } from "./VerdictChip";

interface FindingsTableProps {
  indicators: Indicator[];
  query: string;
  empty: string;
  onWhitelist: (indicator: Indicator) => void;
  onBlacklist: (indicator: Indicator) => void;
}

function isListable(indicator: Indicator): boolean {
  if (indicator.classification === "private" || indicator.classification === "internal") return false;
  return indicator.verdict !== "whitelisted" && indicator.verdict !== "blacklisted";
}

function matches(indicator: Indicator, query: string): boolean {
  if (!query) return true;
  return [
    indicator.value,
    indicator.type,
    indicator.verdict,
    indicator.classification,
    ...(indicator.domains ?? []),
    ...(indicator.processes ?? []),
  ]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

export function FindingsTable({ indicators, query, empty, onWhitelist, onBlacklist }: FindingsTableProps) {
  const visible = indicators.filter((indicator) => matches(indicator, query));

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Indicator</th>
            <th>Verdict</th>
            <th className="num">Detections</th>
            <th>Process / route</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {visible.length === 0 ? (
            <tr>
              <td colSpan={5} className="table-empty">
                {empty}
              </td>
            </tr>
          ) : (
            visible.map((indicator) => {
              const vt = indicator.vt;
              return (
                <tr
                  key={`${indicator.type}:${indicator.value}`}
                  data-tone={
                    indicator.verdict === "blacklisted" || indicator.verdict === "malicious"
                      ? "red"
                      : indicator.verdict === "suspicious"
                        ? "amber"
                        : undefined
                  }
                >
                  <td>
                    <div className="cell-main">
                      <Tag>{indicator.type === "ip" ? "IP" : "Domain"}</Tag>
                      <span className="mono strong break">{indicator.value}</span>
                    </div>
                    {indicator.blacklist_match ? (
                      <div className="cell-sub">
                        blacklisted via {indicator.blacklist_match}
                        {indicator.whitelist_match ? ` · also whitelisted via ${indicator.whitelist_match}` : ""}
                      </div>
                    ) : indicator.whitelist_match ? (
                      <div className="cell-sub">whitelisted via {indicator.whitelist_match}</div>
                    ) : (indicator.domains ?? []).length ? (
                      <div className="cell-sub">{indicator.domains?.join(", ")}</div>
                    ) : null}
                  </td>
                  <td>
                    <VerdictChip verdict={indicator.verdict} />
                  </td>
                  <td className="num">{vt?.detections || "—"}</td>
                  <td>
                    <div className="cell-value">
                      {(indicator.processes ?? []).length
                        ? indicator.processes?.join(", ")
                        : indicator.type === "domain"
                          ? "DNS cache"
                          : "—"}
                    </div>
                    {indicator.connections ? (
                      <div className="cell-sub">
                        {indicator.connections} connection{indicator.connections > 1 ? "s" : ""}
                      </div>
                    ) : null}
                    {vt?.error ? <div className="cell-sub">{vt.error}</div> : null}
                  </td>
                  <td>
                    <div className="row-actions">
                      {vt?.link ? (
                        <a
                          className="icon-btn"
                          href={vt.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          aria-label={`Open VirusTotal report for ${indicator.value}`}
                          title="VirusTotal report"
                        >
                          <Icon name="external" />
                        </a>
                      ) : null}
                      {isListable(indicator) ? (
                        <>
                          <button
                            type="button"
                            className="icon-btn"
                            onClick={() => onWhitelist(indicator)}
                            aria-label={`Whitelist ${indicator.value}`}
                            title="Whitelist and re-run"
                          >
                            <Icon name="check" />
                          </button>
                          <button
                            type="button"
                            className="icon-btn icon-btn--danger"
                            onClick={() => onBlacklist(indicator)}
                            aria-label={`Blacklist ${indicator.value}`}
                            title="Blacklist and re-run"
                          >
                            <Icon name="ban" />
                          </button>
                        </>
                      ) : null}
                    </div>
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
