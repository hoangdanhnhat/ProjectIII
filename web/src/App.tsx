import { lazy, Suspense } from "react";
import { TopBar } from "./components/layout/TopBar";
import { ConnectView } from "./components/layout/ConnectView";
import { ConnectedView } from "./components/layout/ConnectedView";
import { Skeleton } from "./components/ui/Skeleton";
import { useSession } from "./hooks/useSession";
import { useTheme } from "./hooks/useTheme";

const Gallery = lazy(() => import("./dev/Gallery"));

function wantsGallery(): boolean {
  return import.meta.env.DEV && new URLSearchParams(window.location.search).has("gallery");
}

export default function App() {
  const session = useSession();
  const { theme, toggle } = useTheme();

  if (wantsGallery()) {
    return (
      <Suspense fallback={null}>
        <Gallery theme={theme} onToggleTheme={toggle} />
      </Suspense>
    );
  }

  const meta = session.meta;

  return (
    <>
      <TopBar
        theme={theme}
        onToggleTheme={toggle}
        connected={meta !== null}
        hostId={meta?.host_id}
        onDisconnect={session.disconnect}
      />
      <main className="main">
        {meta ? (
          <ConnectedView hostId={meta.host_id} scenarios={meta.scenarios} />
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
    </>
  );
}
