import type { Verdict } from "../../api/types";
import { Chip, type Tone } from "../ui/Chip";

const VERDICTS: Record<Verdict, { label: string; tone: Tone }> = {
  blacklisted: { label: "Blacklisted", tone: "red" },
  malicious: { label: "Malicious", tone: "red" },
  suspicious: { label: "Suspicious", tone: "amber" },
  clean: { label: "Clean", tone: "green" },
  unrated: { label: "Unrated", tone: "neutral" },
  whitelisted: { label: "Whitelisted", tone: "neutral" },
  private: { label: "Private", tone: "neutral" },
  skipped: { label: "Skipped", tone: "neutral" },
};

export function VerdictChip({ verdict }: { verdict: Verdict }) {
  const info = VERDICTS[verdict] ?? { label: verdict, tone: "neutral" as Tone };
  return <Chip tone={info.tone}>{info.label}</Chip>;
}
