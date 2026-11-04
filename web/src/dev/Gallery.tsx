import { useState } from "react";
import { Button } from "../components/ui/Button";
import { Chip } from "../components/ui/Chip";
import { Dialog, DialogHead } from "../components/ui/Dialog";
import { EmptyState } from "../components/ui/EmptyState";
import { Field, TextInput } from "../components/ui/Field";
import { Icon } from "../components/ui/Icon";
import { Skeleton } from "../components/ui/Skeleton";
import { Tag } from "../components/ui/Tag";
import { ToastProvider } from "../components/ui/Toasts";
import { useToast } from "../components/ui/toast-context";
import type { Theme } from "../hooks/useTheme";

interface GalleryProps {
  theme: Theme;
  onToggleTheme: () => void;
}

const TABS = ["Findings", "Connections", "DNS cache"];

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-head">
        <h2>{title}</h2>
      </div>
      <div className="panel-body">{children}</div>
    </section>
  );
}

function Demo() {
  const toast = useToast();
  const [tab, setTab] = useState(TABS[0]);
  const [open, setOpen] = useState(false);

  return (
    <>
      <Section title="Buttons">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Button variant="primary">Primary</Button>
          <Button>Secondary</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="primary" icon="plus">
            With icon
          </Button>
          <Button small variant="primary">
            Small
          </Button>
          <Button busy>Working…</Button>
          <Button disabled>Disabled</Button>
          <button type="button" className="icon-btn" aria-label="Settings">
            <Icon name="globe" />
          </button>
        </div>
      </Section>

      <Section title="Chips and tags">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <Chip>Queued</Chip>
          <Chip tone="green">Clean</Chip>
          <Chip tone="amber">Suspicious</Chip>
          <Chip tone="red">Malicious</Chip>
          <Chip tone="red">Blacklisted</Chip>
          <Chip tone="blue">Running</Chip>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 12 }}>
          <Tag>IP</Tag>
          <Tag>Domain</Tag>
          <Tag>Netstat &amp; DNS</Tag>
        </div>
      </Section>

      <Section title="Fields">
        <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}>
          <Field label="Operator token" htmlFor="demo-token" hint="Stored in session storage only.">
            <TextInput id="demo-token" type="password" placeholder="Paste token" />
          </Field>
          <Field label="Rate limit" htmlFor="demo-rate" optional>
            <TextInput id="demo-rate" type="number" defaultValue={4} />
          </Field>
          <Field label="With error" htmlFor="demo-error" error="Value must be an IPv4 address.">
            <TextInput id="demo-error" defaultValue="999.1.1.1" />
          </Field>
        </div>
      </Section>

      <Section title="Tabs">
        <div className="tabs" role="group" aria-label="Demo tabs">
          {TABS.map((name) => (
            <button
              key={name}
              type="button"
              className={name === tab ? "tab is-active" : "tab"}
              onClick={() => setTab(name)}
              aria-pressed={name === tab}
            >
              {name} <span className="count">3</span>
            </button>
          ))}
        </div>
      </Section>

      <Section title="Table">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Verdict</th>
                <th className="num">Detections</th>
                <th>Process</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="strong mono">93.184.216.34</td>
                <td>
                  <Chip tone="red">Malicious</Chip>
                </td>
                <td className="num">7/92</td>
                <td>chrome.exe (4020)</td>
              </tr>
              <tr>
                <td className="strong mono">cdn.example.net</td>
                <td>
                  <Chip tone="green">Clean</Chip>
                </td>
                <td className="num">0/80</td>
                <td>DNS cache</td>
              </tr>
              <tr>
                <td className="strong mono">10.0.0.9</td>
                <td>
                  <Chip>Private</Chip>
                </td>
                <td className="num">—</td>
                <td>System (4)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="States">
        <div style={{ display: "grid", gap: 10 }}>
          <Skeleton />
          <Skeleton />
        </div>
        <EmptyState
          title="No collections yet"
          description="Queue a collection to pull evidence from the registered host."
        />
      </Section>

      <Section title="Dialog and toasts">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Button onClick={() => setOpen(true)}>Open dialog</Button>
          <Button onClick={() => toast("Settings saved.", "success")}>Success toast</Button>
          <Button onClick={() => toast("Could not reach the server.", "error")}>Error toast</Button>
          <Button onClick={() => toast("Re-running the check.")}>Info toast</Button>
        </div>
        <Dialog open={open} onClose={() => setOpen(false)} labelledBy="demo-dialog-title">
          <DialogHead
            id="demo-dialog-title"
            eyebrow="Example"
            title="Native modal dialog"
            onClose={() => setOpen(false)}
          />
          <div className="dialog-body">
            <Field label="Host ID" htmlFor="demo-host">
              <TextInput id="demo-host" defaultValue="lab-ubuntu" />
            </Field>
          </div>
          <footer className="dialog-foot">
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={() => setOpen(false)}>
              Save
            </Button>
          </footer>
        </Dialog>
      </Section>

      <p className="fineprint">
        Development-only component gallery. Open the console at <code className="mono">/next/?gallery</code> (or
        the Vite dev server with <code className="mono">?gallery</code>).
      </p>
    </>
  );
}

export default function Gallery({ theme, onToggleTheme }: GalleryProps) {
  return (
    <ToastProvider>
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <span className="brand-name">Design system</span>
            <span className="brand-sub">Gallery</span>
          </div>
          <div className="topbar-actions">
            <Button variant="ghost" small onClick={onToggleTheme}>
              {theme === "dark" ? "Light theme" : "Dark theme"}
            </Button>
          </div>
        </div>
      </header>
      <main className="main">
        <Demo />
      </main>
    </ToastProvider>
  );
}
