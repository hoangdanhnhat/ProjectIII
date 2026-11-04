import type { DNSRecord } from "../../api/types";
import { Tag } from "../ui/Tag";

interface DnsTableProps {
  records: DNSRecord[];
  flagged: Map<string, string>;
  query: string;
  empty: string;
}

function matches(record: DNSRecord, query: string): boolean {
  if (!query) return true;
  return [record.name, record.type, record.data, String(record.ttl ?? "")]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

export function DnsTable({ records, flagged, query, empty }: DnsTableProps) {
  const visible = records.filter((record) => matches(record, query));

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th className="num">TTL</th>
            <th>Data</th>
          </tr>
        </thead>
        <tbody>
          {visible.length === 0 ? (
            <tr>
              <td colSpan={4} className="table-empty">
                {empty}
              </td>
            </tr>
          ) : (
            visible.map((record) => (
              <tr key={`${record.name}:${record.type}:${record.data}`} data-tone={flagged.get(record.name)}>
                <td>
                  <span className="mono break">{record.name}</span>
                </td>
                <td>
                  <Tag>{record.type}</Tag>
                </td>
                <td className="num">{record.ttl ? `${record.ttl}s` : "—"}</td>
                <td>
                  <span className="mono break">{record.data}</span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
