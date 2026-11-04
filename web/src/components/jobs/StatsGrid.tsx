import { Icon, type IconName } from "../ui/Icon";
import type { jobCounts } from "../../lib/jobFilters";

interface StatsGridProps {
  counts: ReturnType<typeof jobCounts>;
}

const CARDS: Array<{ key: keyof ReturnType<typeof jobCounts>; label: string; hint: string; icon: IconName }> = [
  { key: "total", label: "Total", hint: "all collections", icon: "layers" },
  { key: "active", label: "Active", hint: "queued or running", icon: "activity" },
  { key: "completed", label: "Completed", hint: "fully collected", icon: "check-circle" },
  { key: "attention", label: "Attention", hint: "partial, failed, skipped", icon: "alert" },
];

export function StatsGrid({ counts }: StatsGridProps) {
  return (
    <div className="stats">
      {CARDS.map((card) => (
        <article className="stat" key={card.key}>
          <div className="stat-icon">
            <Icon name={card.icon} />
          </div>
          <div className="stat-copy">
            <span className="stat-label">{card.label}</span>
            <strong className="stat-value">{counts[card.key]}</strong>
            <span className="stat-hint">{card.hint}</span>
          </div>
        </article>
      ))}
    </div>
  );
}
