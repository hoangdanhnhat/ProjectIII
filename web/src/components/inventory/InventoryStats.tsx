import type { Host } from "../../api/types";
import { Icon, type IconName } from "../ui/Icon";

interface InventoryStatsProps {
  hosts: Host[];
}

function counts(hosts: Host[]) {
  let automatic = 0;
  let manual = 0;
  let attention = 0;
  for (const host of hosts) {
    if (host.role_source === "manual") manual += 1;
    else automatic += 1;
    if (host.status === "stale" || host.status === "offline") attention += 1;
  }
  return { total: hosts.length, automatic, manual, attention };
}

const CARDS: Array<{ key: keyof ReturnType<typeof counts>; label: string; hint: string; icon: IconName }> = [
  { key: "total", label: "Machines", hint: "in inventory", icon: "server" },
  { key: "automatic", label: "Automatic", hint: "role detection", icon: "activity" },
  { key: "manual", label: "Manual", hint: "operator override", icon: "key" },
  { key: "attention", label: "Attention", hint: "stale or offline", icon: "alert" },
];

export function InventoryStats({ hosts }: InventoryStatsProps) {
  const values = counts(hosts);
  return (
    <div className="stats">
      {CARDS.map((card) => (
        <article className="stat" key={card.key}>
          <div className="stat-icon">
            <Icon name={card.icon} />
          </div>
          <div className="stat-copy">
            <span className="stat-label">{card.label}</span>
            <strong className="stat-value">{values[card.key]}</strong>
            <span className="stat-hint">{card.hint}</span>
          </div>
        </article>
      ))}
    </div>
  );
}
