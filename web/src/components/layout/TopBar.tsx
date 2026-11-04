import { Button } from "../ui/Button";
import { Icon } from "../ui/Icon";
import type { Theme } from "../../hooks/useTheme";

interface TopBarProps {
  theme: Theme;
  onToggleTheme: () => void;
  connected: boolean;
  hostId?: string;
  onDisconnect: () => void;
}

export function TopBar({ theme, onToggleTheme, connected, hostId, onDisconnect }: TopBarProps) {
  const themeLabel = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <a className="brand" href={import.meta.env.BASE_URL} aria-label="Evidence Console home">
          <span className="brand-name">Evidence Console</span>
          <span className="brand-sub">DFIR</span>
        </a>
        <div className="topbar-actions">
          {connected ? (
            <span className="statusline">
              <span className="status-dot" data-state="ok" />
              {hostId}
            </span>
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
