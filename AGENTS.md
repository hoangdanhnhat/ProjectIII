# AGENTS.md — working in this repository

Instructions and conventions for AI agents (and humans) changing this
codebase. Read this before editing; keep it up to date when conventions
change.

## What this repository is

- `cmd/dfir-server` — coordination server (Go): job queue, evidence store,
  operator API, embedded web console.
- `cmd/dfir-agent` — Windows endpoint agent (Go): scenario collectors.
- `internal/collector/*` — one package per scenario (`webshell`, `netstat`,
  `eventlog`); pure rendering/correlation logic is platform-neutral and
  unit-tested on Linux, OS APIs live in `*_windows.go`.
- `internal/ti` — threat-intel engine: settings, white/black lists,
  VirusTotal client, enrichment.
- `internal/webui` — embeds the consoles (`static/` legacy, `dist/` React).
- `web/` — React console (TypeScript, Vite, TanStack Query, Vitest).
- `deploy/` — Docker lab, systemd/Windows service templates.
- `SETUP.md` — operator setup guide. `README.md` — feature reference.

## Commands

```bash
make lab-up            # build + start the server container (data/ persists)
make lab-job SCENARIO=netstat.v1

# Front-end (npm runs in a Node 22 container; no host toolchain needed)
make web-install       # npm ci
make web-dev           # Vite on :5173, proxies /v1 to :8080
make web-build         # writes internal/webui/dist (embedded at go build)
make web-check         # typecheck + ESLint + Stylelint + Vitest

# Go
go test ./...          # module root; web/ is a separate module boundary
go vet ./...
gofmt -w cmd internal
GOOS=windows go build ./...   # agent code compiles for Windows
```

Verify before committing: `go test ./...`, `make web-check`, and for
agent/collector changes `GOOS=windows go vet ./...`.

## Front-end architecture (web/)

```text
src/
  api/        client.ts (only fetch wrapper), types.ts (all API payloads)
  hooks/      useSession, useTheme, useHashJob (no hidden state libraries)
  components/
    ui/       primitives: Button, Chip, Tag, Field, Dialog, Toasts, ...
    layout/   TopBar, ConnectView, shell
    jobs/     dashboard  (phase 3)
    detail/   job sheet  (phase 4)
    ti/       triage + settings (phase 4)
  styles/     tokens.css (the only literal colors), base.css, components.css
  dev/        Gallery.tsx — dev-only primitive gallery (?gallery)
  test/       setup, fixtures, MSW handlers, token/contrast tests
```

Rules:

1. **One component per file**, named export, `< 260` lines (ESLint warns).
   Helpers used by one component live beside it; shared helpers go in
   `hooks/` or `api/`.
2. **Strict TypeScript.** No `any` (lint error), no non-null assertions for
   convenience, no `@ts-ignore`. Add payload shapes to `api/types.ts` first.
3. **All server access through `api/client.ts`.** Never call `fetch`
   directly from a component. Query keys are declared where the hook lives
   and mutations invalidate the exact keys they affect.
4. **Render text as JSX.** `dangerouslySetInnerHTML` is forbidden (lint
   error) and inline `<script>` tags are blocked by the server CSP.
5. **Styling**: classes from `styles/components.css`; colors only via
   `var(--token)`; no literal hex outside `styles/tokens.css` (Stylelint).
   Inline `style` is only for one-off layout (width, height), never color.
6. **Both themes are mandatory.** Every visual change must be checked in
   light and dark (the token contrast test enforces AA for the documented
   pairs).
7. **Accessibility**: label every control, keep native `<dialog>` semantics,
   keep keyboard flow (ESC closes, focus rings visible).
8. **Tests**: component/behavior changes get a Vitest + Testing Library
   test; API interactions go through MSW handlers, not real network.

## Color is meaning

Neutral by default; red = malicious/blacklisted, amber = suspicious/partial,
green = clean/completed, everything else muted gray. Do not add decorative
colors, gradients, glows, or icon tints. Status chips use a dot + label, so
meaning never depends on hue alone.

## Adding things (recipes)

**A new verdict** (`internal/ti/report.go` + console):
1. Add the constant, count it in `Summary`, decide its severity rank in
   `RenderReport`.
2. Extend the engine switches (`needsQuery`, `summarize`).
3. Add the label/tone to `VERDICTS` in the console and a test.

**A new list-managed value type** (`internal/ti/lists.go`):
1. Extend `ParseEntryValue` (normalize + validate) and `MatchIP`/
   `MatchDomain` if the type is not IP/domain based.
2. Add tests for parse, match, and persistence; the console list manager
   needs no change unless the type is new to users.

**A new screen/section**: create `components/<area>/<Name>.tsx`, compose
primitives, add a route entry in `App.tsx`, add a test, and (if it is
user-visible) a sentence in `README.md`.

**A new API endpoint**: implement it in Go, add the type to
`api/types.ts`, the call in `api/queries.ts`, and an MSW handler + test.

## Migration status (front-end rewrite)

- Legacy vanilla console is served at `/` from `internal/webui/static/`.
- The React console is served at `/next/` from `internal/webui/dist/`.
- `web/vite.config.ts` sets `base: "/next/"`; at cutover flip it to `/`,
  point `Handler()` at the dist bundle, delete `static/`, and update
  `internal/webui/webui_test.go`.
- `internal/webui/dist/.embed` is committed so `go build` works before a
  front-end build; `vite build` recreates the marker. Never commit the rest
  of `dist/` or `web/node_modules/` (gitignored).

## Evidence and security invariants (do not weaken)

- Raw evidence artifacts are immutable: enrichment writes a **new**
  `ti_report` artifact and never rewrites the snapshot.
- Downloads verify SHA-256 before serving; keep it that way.
- The operator token stays in `sessionStorage`; the VirusTotal key never
  leaves the server (`data/ti_config.json`, 0600).
- CSP, `nosniff`, `frame-ancestors 'none'` headers are non-negotiable.
- Collectors never run arbitrary commands; only vetted system binaries with
  fixed arguments (`wevtutil`, `Get-DnsClientCache`) and no symlink
  following.
