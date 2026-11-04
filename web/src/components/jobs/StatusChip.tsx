import type { JobStatus } from "../../api/types";
import { Chip, type Tone } from "../ui/Chip";

const STATUS: Record<JobStatus, { label: string; tone: Tone }> = {
  queued: { label: "Queued", tone: "neutral" },
  running: { label: "Running", tone: "blue" },
  completed: { label: "Completed", tone: "green" },
  partial: { label: "Partial", tone: "amber" },
  failed: { label: "Failed", tone: "red" },
  skipped: { label: "Skipped", tone: "neutral" },
  needs_configuration: { label: "Needs config", tone: "neutral" },
};

export function StatusChip({ status }: { status: JobStatus }) {
  const info = STATUS[status] ?? { label: status, tone: "neutral" as Tone };
  return <Chip tone={info.tone}>{info.label}</Chip>;
}
