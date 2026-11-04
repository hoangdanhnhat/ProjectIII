import type { TIStatus } from "../../api/types";
import { Chip, type Tone } from "../ui/Chip";

const STATUS: Record<TIStatus, { label: string; tone: Tone }> = {
  running: { label: "TI running", tone: "blue" },
  completed: { label: "TI completed", tone: "green" },
  partial: { label: "TI partial", tone: "amber" },
  skipped: { label: "TI skipped", tone: "neutral" },
  failed: { label: "TI failed", tone: "red" },
  interrupted: { label: "TI interrupted", tone: "neutral" },
};

export function TIStatusChip({ status }: { status: string }) {
  const info = STATUS[status as TIStatus];
  if (!info) return null;
  return <Chip tone={info.tone}>{info.label}</Chip>;
}
