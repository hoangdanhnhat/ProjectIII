const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const ABSOLUTE = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
const SHORT = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

export function asDate(value?: string | null): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function relative(value?: string | null): string {
  const date = asDate(value);
  if (!date) return "—";
  const diff = (date.getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  if (abs >= 86400) return RELATIVE.format(Math.round(diff / 86400), "day");
  if (abs >= 3600) return RELATIVE.format(Math.round(diff / 3600), "hour");
  return RELATIVE.format(Math.round(diff / 60), "minute");
}

export function absolute(value?: string | null): string {
  const date = asDate(value);
  return date ? ABSOLUTE.format(date) : "—";
}

export function shortTime(value?: string | null): string {
  const date = asDate(value);
  return date ? SHORT.format(date) : "—";
}

export function duration(job: { created_at: string; started_at?: string | null; ended_at?: string | null; status: string }): string {
  const start = asDate(job.started_at || job.created_at);
  if (!start) return "—";
  const end = asDate(job.ended_at) || (job.status === "running" ? new Date() : null);
  if (!end) return "—";
  const ms = end.getTime() - start.getTime();
  if (Number.isNaN(ms) || ms < 0) return "—";
  if (ms < 1000) return "<1s";
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function bytes(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value;
  let index = -1;
  do {
    size /= 1024;
    index += 1;
  } while (size >= 1024 && index < units.length - 1);
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`;
}

export function shortId(id?: string): string {
  if (!id) return "—";
  return id.length > 14 ? `${id.slice(0, 12)}…` : id;
}

export function shortHash(hash?: string): string {
  if (!hash) return "—";
  return `${hash.slice(0, 16)}…`;
}

export function fileName(source?: string, fallback?: string): string {
  const parts = String(source ?? "").split(/[\\/]/);
  const base = parts[parts.length - 1]?.trim();
  return base || `artifact-${String(fallback ?? "download").slice(0, 8)}`;
}
