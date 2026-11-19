import { useState } from "react";
import type { VolatilityPluginResult } from "../../api/types";
import { useArtifactJSONL } from "../../api/queries";
import { Button } from "../ui/Button";
import { Dialog, DialogHead } from "../ui/Dialog";
import { Icon } from "../ui/Icon";

interface PluginTableDialogProps {
  jobId: string;
  token: string;
  plugin: VolatilityPluginResult;
  onClose: () => void;
}

const MAX_VISIBLE_ROWS = 500;

function cellValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function columnsOf(rows: Array<Record<string, unknown>>): string[] {
  const columns: string[] = [];
  const seen = new Set<string>();
  for (const row of rows.slice(0, 50)) {
    for (const key of Object.keys(row)) {
      if (!seen.has(key)) {
        seen.add(key);
        columns.push(key);
      }
    }
  }
  return columns;
}

/** PluginTableDialog renders one Volatility JSONL artifact as a searchable table. */
export function PluginTableDialog({ jobId, token, plugin, onClose }: PluginTableDialogProps) {
  const query = useArtifactJSONL<Record<string, unknown>>(
    token,
    jobId,
    plugin.artifact_id ?? null,
  );
  const [search, setSearch] = useState("");
  const rows = query.data ?? [];
  const columns = columnsOf(rows);
  const needle = search.trim().toLowerCase();
  const filtered = needle
    ? rows.filter((row) =>
        columns.some((column) => cellValue(row[column]).toLowerCase().includes(needle)),
      )
    : rows;
  const visible = filtered.slice(0, MAX_VISIBLE_ROWS);

  return (
    <Dialog open onClose={onClose} labelledBy="plugin-table-title" className="wide">
      <DialogHead
        id="plugin-table-title"
        eyebrow="Volatility output"
        title={plugin.name}
        onClose={onClose}
      />
      <div className="dialog-body">
        {query.isLoading ? (
          <div className="mini-empty">Loading plugin output…</div>
        ) : query.error ? (
          <div className="mini-empty">Could not load plugin output: {query.error.message}</div>
        ) : rows.length === 0 ? (
          <div className="mini-empty">This plugin produced no rows.</div>
        ) : (
          <>
            <div className="search">
              <Icon name="search" className="icon search-icon" />
              <input
                type="search"
                placeholder="Filter rows…"
                aria-label={`Filter ${plugin.name} rows`}
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                autoComplete="off"
              />
            </div>
            <div className="table-wrap plugin-table">
              <table className="table" aria-label={`${plugin.name} rows`}>
                <thead>
                  <tr>
                    {columns.map((column) => (
                      <th key={column} className="mono">
                        {column}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {visible.length === 0 ? (
                    <tr>
                      <td colSpan={columns.length} className="table-empty">
                        No rows match the filter.
                      </td>
                    </tr>
                  ) : (
                    visible.map((row, index) => (
                      <tr key={index}>
                        {columns.map((column) => (
                          <td key={column} className="mono">
                            {cellValue(row[column])}
                          </td>
                        ))}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            <p className="artifact-meta">
              Showing {visible.length} of {filtered.length} rows
              {filtered.length > MAX_VISIBLE_ROWS
                ? ` (first ${MAX_VISIBLE_ROWS} displayed; download the artifact for the full output)`
                : filtered.length !== rows.length
                  ? ` of ${rows.length} total`
                  : ""}
            </p>
          </>
        )}
      </div>
      <footer className="dialog-foot">
        <Button onClick={onClose}>Close</Button>
      </footer>
    </Dialog>
  );
}
