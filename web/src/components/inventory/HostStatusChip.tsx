import type { HostStatus } from "../../api/types";
import { Chip, type Tone } from "../ui/Chip";

const STATUS: Record<HostStatus, { label: string; tone: Tone }> = {
  online: { label: "Online", tone: "green" },
  stale: { label: "Stale", tone: "amber" },
  offline: { label: "Offline", tone: "neutral" },
  never_seen: { label: "Never seen", tone: "neutral" },
};

export function HostStatusChip({ status }: { status: HostStatus }) {
  const info = STATUS[status] ?? { label: status, tone: "neutral" as Tone };
  return <Chip tone={info.tone}>{info.label}</Chip>;
}
