import type { SnapshotConnection } from "../../api/types";

interface ConnectionsTableProps {
  connections: SnapshotConnection[];
  flagged: Map<string, string>;
  query: string;
  empty: string;
}

function matches(connection: SnapshotConnection, query: string): boolean {
  if (!query) return true;
  return [
    connection.remote_addr,
    connection.local_addr,
    connection.proto,
    connection.state ?? "",
    connection.process ?? "",
    String(connection.pid),
    ...(connection.domains ?? []),
  ]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

export function ConnectionsTable({ connections, flagged, query, empty }: ConnectionsTableProps) {
  const visible = connections.filter((connection) => matches(connection, query));

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Remote</th>
            <th>Local</th>
            <th>Proto · state</th>
            <th>Process</th>
            <th>Domains</th>
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
            visible.map((connection, index) => (
              <tr key={`${connection.proto}:${connection.local_port}:${connection.pid}:${index}`} data-tone={flagged.get(connection.remote_addr)}>
                <td>
                  <span className="mono strong">
                    {connection.remote_addr
                      ? `${connection.remote_addr}:${connection.remote_port}`
                      : "—"}
                  </span>
                </td>
                <td>
                  <span className="mono">{`${connection.local_addr}:${connection.local_port}`}</span>
                </td>
                <td>
                  {connection.proto}
                  {connection.state ? <div className="cell-sub">{connection.state}</div> : null}
                </td>
                <td>
                  {connection.process || "—"}
                  <div className="cell-sub">pid {connection.pid}</div>
                </td>
                <td>{(connection.domains ?? []).join(", ") || "—"}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
