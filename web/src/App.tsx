import { lazy, Suspense, useEffect, useState } from "react";
import { TopBar, type AppView } from "./components/layout/TopBar";
import { ConnectView } from "./components/layout/ConnectView";
import { Dashboard } from "./components/layout/Dashboard";
import { InventoryPage } from "./components/inventory/InventoryPage";
import { MemoryPage } from "./components/memory/MemoryPage";
import { TISettingsDialog } from "./components/settings/TISettingsDialog";
import { Skeleton } from "./components/ui/Skeleton";
import { useSession } from "./hooks/useSession";
import { useTheme } from "./hooks/useTheme";

const Gallery = lazy(() => import("./dev/Gallery"));

function wantsGallery(): boolean {
  return import.meta.env.DEV && new URLSearchParams(window.location.search).has("gallery");
}

function currentView(): AppView {
  if (window.location.hash.startsWith("#/machines")) return "machines";
  if (window.location.hash.startsWith("#/memory")) return "memory";
  return "collections";
}

export default function App() {
  const session = useSession();
  const { theme, toggle } = useTheme();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [view, setView] = useState<AppView>(currentView);

  useEffect(() => {
    const sync = () => setView(currentView());
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);

  if (wantsGallery()) {
    return (
      <Suspense fallback={null}>
        <Gallery theme={theme} onToggleTheme={toggle} />
      </Suspense>
    );
  }

  const meta = session.meta;
  const connected = meta !== null && session.token !== "";

  return (
    <>
      <TopBar
        theme={theme}
        onToggleTheme={toggle}
        connected={connected}
        hostId={meta?.host_id}
        hosts={meta?.hosts}
        view={view}
        onOpenSettings={() => setSettingsOpen(true)}
        onDisconnect={session.disconnect}
      />
      <main className="main">
        {meta ? (
          view === "machines" ? (
            <InventoryPage token={session.token} meta={meta} />
          ) : view === "memory" ? (
            <MemoryPage token={session.token} meta={meta} />
          ) : (
            <Dashboard token={session.token} meta={meta} />
          )
        ) : session.restoring ? (
          <section className="connect" aria-busy="true">
            <div className="connect-card">
              <div className="eyebrow">Session</div>
              <h1>Restoring session…</h1>
              <div className="restore-stack">
                <Skeleton />
                <Skeleton />
              </div>
            </div>
          </section>
        ) : (
          <ConnectView
            error={session.error}
            onConnect={session.connect}
            onClearError={session.clearError}
          />
        )}
      </main>

      {settingsOpen && connected ? (
        <TISettingsDialog token={session.token} onClose={() => setSettingsOpen(false)} />
      ) : null}
    </>
  );
}
