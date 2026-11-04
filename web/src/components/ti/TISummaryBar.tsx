import type { TISummary } from "../../api/types";
import { Chip, type Tone } from "../ui/Chip";

const ORDER: Array<{ key: keyof TISummary; label: string; tone: Tone }> = [
  { key: "blacklisted", label: "Blacklisted", tone: "red" },
  { key: "malicious", label: "Malicious", tone: "red" },
  { key: "suspicious", label: "Suspicious", tone: "amber" },
  { key: "clean", label: "Clean", tone: "green" },
  { key: "whitelisted", label: "Whitelisted", tone: "neutral" },
  { key: "unrated", label: "Unrated", tone: "neutral" },
  { key: "skipped", label: "Skipped", tone: "neutral" },
  { key: "private", label: "Private", tone: "neutral" },
];

export function TISummaryBar({ summary }: { summary: TISummary }) {
  return (
    <div className="ti-summary">
      {ORDER.map((entry) => {
        const count = summary[entry.key];
        if (!count) return null;
        return (
          <Chip key={entry.key} tone={entry.tone} title={entry.label}>
            {count} {entry.label}
          </Chip>
        );
      })}
    </div>
  );
}
