import { Button } from "../ui/Button";
import { Icon } from "../ui/Icon";
import type { Theme } from "../../hooks/useTheme";

export type AppView = "collections" | "machines";

interface TopBarProps {
  theme: Theme;
  onToggleTheme: () => void;
  connected: boolean;
  hostId?: string;
  hosts?: string[];
  view: AppView;
  onOpenSettings: () => void;
  onDisconnect: () => void;
}

export function TopBar({
  theme,
  onToggleTheme,
  connected,
  hostId,
  hosts = [],
  view,
  onOpenSettings,
  onDisconnect,
}: TopBarProps) {
  const themeLabel = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <a className="brand" href={import.meta.env.BASE_URL} aria-label="Evidence Console home">
          <span className="brand-name">Evidence Console</span>
          <span className="brand-sub">DFIR</span>
        </a>
        {connected ? (
          <nav className="topbar-nav" aria-label="Primary">
            <a
              className={view === "collections" ? "nav-link is-active" : "nav-link"}
              href="#/"
            >
              Collections
            </a>
            <a
              className={view === "machines" ? "nav-link is-active" : "nav-link"}
              href="#/machines"
            >
              Machines
            </a>
          </nav>
        ) : null}
        <div className="topbar-actions">
          {connected ? (
            <span className="statusline" title={hosts.join(", ")}>
              <span className="status-dot" data-state={hostId ? "ok" : undefined} />
              {hostId || "No hosts"}
              {hosts.length > 1 ? ` +${hosts.length - 1}` : ""}
            </span>
          ) : null}
          {connected ? (
            <Button variant="ghost" small icon="key" onClick={onOpenSettings}>
              Threat Intel
            </Button>
          ) : null}
          <button
            type="button"
            className="icon-btn"
            onClick={onToggleTheme}
            aria-label={themeLabel}
            title={themeLabel}
          >
            <Icon name={theme === "dark" ? "sun" : "moon"} />
          </button>
          {connected ? (
            <Button variant="ghost" small onClick={onDisconnect}>
              Disconnect
            </Button>
          ) : null}
        </div>
      </div>
    </header>
  );
}
