# DFIR/CA evidence collector — server + Windows agent

Prototype consisting of an orchestrating server and a **Windows agent**, both written in Go. The server runs in Docker on a Linux machine (or anywhere Go builds); the agent runs on the Windows endpoint being monitored and connects **outbound only** — it never listens for inbound connections. Current scope: Windows 10/11 and Windows Server 64-bit hosts, scenarios `netstat.v1`, `eventlog.v1`, `webshell.v1` and `hostrole.v1`, plus automated **Threat Intelligence triage** of network connections via VirusTotal.

> **Setting this up from scratch?** Follow the step-by-step guide in [SETUP.md](SETUP.md) — server, Windows agent, VirusTotal key and first collection, including troubleshooting.
>
> **Working on the code?** See [AGENTS.md](AGENTS.md) for the repository layout, commands, front-end conventions and invariants.

For `netstat.v1` the agent snapshots the TCP/UDP connection tables with owning processes **and the DNS client resolver cache** (read via `dnsapi.dll` with cache-only queries, generating zero network traffic; a `Get-DnsClientCache` fallback covers restricted hosts). Cached `A`/`AAAA`/`CNAME` records are correlated to connection remote addresses, so each connection records the domain name(s) it reached. When the job finishes, the server automatically triages the snapshot: public IPs and external domains (private/loopback/link-local addresses and whitelisted values are excluded) are checked against VirusTotal, and the verdicts land in the job as a `ti_report` artifact viewable in the web console. The result is **data for an investigation**, not an assertion of compromise.

For `hostrole.v1` the agent classifies the Windows host against a small set of common host roles: **domain controller**, **web server (IIS)**, **workstation**, **database server (MSSQL)**, **mail server (Exchange)**, **DNS server** and **DHCP server**. It reads only registry keys, service installation keys and fixed file metadata (no file contents, no commands, no network) and emits a versioned `host_role` artifact. Roles carry evidence and a confidence tier (`confirmed` / `probable` / `possible`), so a host can legitimately be reported with several roles; the profile describes what is installed or configured, not what is currently serving traffic. The Windows product type (`WinNT` / `ServerNT` / `LanmanNT`) separates a workstation, a member server and a domain controller even when no server role is detected. Third-party web and database servers are out of scope in schema version 1.

### Inventory and role overrides

Every agent sends a heartbeat to `POST /v1/agent/host` (default every minute) and reports its hostname, OS/build, automatic role summaries and the role revision it has applied. The server keeps one record per host under `data/hosts/` and exposes it in the **Machines** page.

The agent runs automatic role detection at startup and then every `-role-interval` (default **1 hour**). If an operator sets manual roles, the server increments `role_revision`; the agent applies the assignment on its next heartbeat, writes it to its local state file and **stops automatic detection**. **Reset to automatic** clears the manual set and makes the agent re-detect immediately. The manual override changes only the inventory's effective roles; existing `host_role` artifacts are never rewritten.

The agent's local state file defaults to `%ProgramData%\dfir-agent\host_state.json` on Windows and `/var/lib/dfir-agent/host_state.json` on Linux, and can be changed with `-state`. It is written atomically with mode `0600` and contains no secrets.

For `webshell.v1` the agent checks the web server configuration file (IIS `applicationHost.config`) to confirm the host is a web server, reads the **explicitly configured upload directory** (IIS has no standard upload directory, so there is no default on Windows — without `-uploads` the job returns `needs_configuration` instead of scanning the drive) and collects files with script extensions (`.php`, `.phtml`, `.phar`, `.cgi`, `.pl`, `.py`, `.sh`, `.jsp`, `.aspx`). If the job carries a `since` timestamp, the agent also collects files modified after that moment, and it snapshots the newest IIS logs.

## What the agent collects on Windows

| Scenario | Artifact kinds | What it is |
| --- | --- | --- |
| `netstat.v1` | `netstat_snapshot`, `ti_report` | TCP/UDP connection table with owning processes + DNS client cache with domain correlation (schema v2); the server adds a VirusTotal triage report |
| `eventlog.v1` | `event_log` | Windows event log channels as schema-versioned JSON (one artifact per channel) |
| `webshell.v1` | `upload`, `iis_log` | Script-extension files from the configured upload directory + snapshots of the newest IIS logs |
| `hostrole.v1` | `host_role` | Evidence-backed Windows host role profile (DC, IIS, workstation, MSSQL, Exchange, DNS, DHCP) from registry/service/file metadata |

## Quick start: Docker server + Windows agent

> The full walkthrough with troubleshooting lives in [SETUP.md](SETUP.md); this is the condensed version.

Requirements: a Linux machine with Docker + compose v2, `openssl` and `make`; a Windows 10/11 64-bit machine with PowerShell (Administrator for `eventlog.v1` with the `Security` channel); both on the same trusted network (the lab currently runs plain HTTP, see the security notes below).

```bash
make lab-init                          # once: random tokens in .env (gitignored)
make lab-up                            # build + start the server only
```

The lab defaults to auto-registration (`DFIR_HOSTS=*`): the server accepts any valid machine hostname presented with the shared agent token, and the agent uses its own hostname as its host ID. To restrict the lab to an explicit allowlist, set a comma-separated list before `make lab-up`:

```bash
# .env
DFIR_HOSTS=lab-ubuntu,win-web01,win-dc01
```

Existing `.env` files created before this behavior may not have `DFIR_HOSTS`; re-run `make lab-init` (it appends `DFIR_HOSTS=*` when missing) or add the line manually and restart the server. If an old allowlist such as `DFIR_HOSTS=lab-ubuntu` is present, change it to `*` to enable hostname auto-registration.

Build the Windows agent — cross-compile from the Linux machine (the Go 1.24 container handles the toolchain; `chown` keeps ownership because the container runs as root):

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.24 sh -c \
  "go build -trimpath -o /src/bin/dfir-agent-windows.exe ./cmd/dfir-agent && chown $(id -u):$(id -g) /src/bin/dfir-agent-windows.exe"
sha256sum bin/dfir-agent-windows.exe  # record this hash
```

Copy `bin/dfir-agent-windows.exe` to the Windows machine (SMB, RDP, scp, or a LAN file server) and run it there with the agent token from `.env`:

```powershell
$env:DFIR_AGENT_TOKEN = '<DFIR_AGENT_TOKEN from .env>'
C:\dfir\dfir-agent.exe `
  -server http://<linux-ip>:8080 `
  -interval 5s
```

`-host-id` is optional. Without it the agent uses the machine hostname, lowercased (`WIN-WEB01` → `win-web01`); the resolved ID is printed at startup. The agent is silent while idle (no job = HTTP 204, nothing printed). It also sends a small inventory heartbeat every minute and refreshes its host roles every hour; see **Inventory and role overrides** below.

Create a job from the Linux machine and wait for the result:

```bash
make lab-job SCENARIO=netstat.v1 HOST=<host-id>     # expect: completed, 1 artifact netstat_snapshot
make lab-job SCENARIO=eventlog.v1 HOST=<host-id>    # expect: completed, 1 artifact event_log per channel
```

In wildcard mode (`DFIR_HOSTS=*`) `HOST` is required; use the machine ID shown on the **Machines** page. With an explicit allowlist, it defaults to the first ID in `DFIR_HOSTS`.

Verify the evidence:

```bash
make lab-status                       # list jobs, newest first
set -a; . ./.env; set +a
curl -sS -H "Authorization: Bearer $DFIR_OPERATOR_TOKEN" \
  http://localhost:8080/v1/jobs/<job-id>/artifacts/<artifact-id> -o evidence.bin
sha256sum evidence.bin                # must match "sha256" in the job JSON
```

Console: `http://localhost:8080/` (log in with `DFIR_OPERATOR_TOKEN` from `.env`). Port conflicts: set `DFIR_CONSOLE_PORT` / `WEB_PORT` in `.env` and re-run `make lab-up`. Teardown: `make lab-down`; full reset (also deletes `data/` and `.env`): `make lab-clean`. The full lab guide, including verified Windows-agent steps and troubleshooting, is in `deploy/docker/README.md` (§4).

## Running the Windows agent

The same `cmd/dfir-agent` source builds for Windows; there is no separate Windows agent program. Build **amd64** even on 64-bit Windows — a 32-bit process sees `System32` through WOW64 redirection and would read the wrong IIS configuration and logs. Requires Go 1.24+ (the secure file helper uses `os.Root`).

```powershell
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -o bin\dfir-agent.exe .\cmd\dfir-agent
$env:DFIR_AGENT_TOKEN = '<agent-token>'
.\bin\dfir-agent.exe -server http://dfir.example:8080 `
  -uploads 'C:\inetpub\wwwroot\uploads' `
  -web-config 'C:\Windows\System32\inetsrv\config\applicationHost.config' `
  -web-logs 'C:\inetpub\logs\LogFiles\W3SVC*\*.log'
```

Flags and behavior:

- `-uploads` **has no default on Windows** (IIS has no standard upload directory). If omitted or not an existing directory, a `webshell.v1` job returns `needs_configuration` instead of scanning the drive; the other scenarios are unaffected.
- `-web-config` defaults to `applicationHost.config` under `%SystemRoot%\System32\inetsrv\config`. It is used for role detection: without IIS the agent reports `skipped` by design. `-web-logs` defaults to the IIS log root (`%SystemDrive%\inetpub\logs\LogFiles\W3SVC*\*.log`).
- `-web-logs` accepts comma-separated paths or glob patterns; globs are expanded and only the **four newest** matches are uploaded (kind `iis_log`), so the server limit of 260 artifacts/job (256 uploads + 4 logs) is never exceeded. The current server accepts the `iis_log` kind; a server binary from before IIS support rejects it with HTTP 400, which the agent treats as a transport failure and retries forever — run the agent with `-web-logs ''` (files only) until the server is rebuilt.
- `-eventlog-channels` defaults to `System,Application`; add `Security` for a domain controller / incident value, which requires running as Administrator.
- `-host-id` is optional; the agent uses the machine hostname (lowercased) when it is omitted and logs the resolved value. Pass it to override collisions or keep a stable ID after a rename.
- `-state` sets the local role cache path; `-heartbeat-interval` defaults to `1m` and `-role-interval` to `1h`. Run the agent as `LocalSystem` for full registry coverage during role detection.
- `-apache-config` / `-apache-logs` are still accepted as aliases of `-web-config` / `-web-logs`.
- The agent reads the config and logs with the account it runs as; to read `applicationHost.config` and all site logs, run it as `LocalSystem` (or grant explicit read ACLs).
- Symlinks, junctions and other reparse points are rejected in every path component. On Windows the agent uses `os.Root` + `Lstat` per component; unlike `O_NOFOLLOW` on Linux, the check/open pair is not atomic, so a same-volume replacement in the race window is not fully prevented.
- It collects only files under the configured upload directory plus the configured log paths — it never scans a whole drive.
- `-hosts '*'` (the lab default) accepts any valid machine hostname with the shared `DFIR_AGENT_TOKEN`; `-hosts a,b,c` restricts the server to an explicit allowlist. All agents still share one token, so any token holder can register any valid hostname in wildcard mode. Per-host tokens/enrollment and revocation are not implemented. Jobs can be queued only for machines that have an inventory record (or are in the allowlist).
- Inventory state is kept per host under `data/hosts/<host-id>.json`. The agent's local role cache defaults to `%ProgramData%\dfir-agent\host_state.json` and can be changed with `-state`.
- Installing the agent as a long-running service (NSSM/WinSW), and whether a separate server build is needed on Windows: see `deploy/windows.md` (TLS is deferred; the lab currently runs HTTP).

## Web console

Open `http://127.0.0.1:8080/` (or the server URL) and log in with `DFIR_OPERATOR_TOKEN`:

- View the collection list with status, duration and artifact count; refreshes automatically every 5 seconds.
- Create new jobs (`host_id`, scenario, optional `since`), open job details and download evidence with its SHA-256.
- **Threat Intel & Lists** settings (top-bar button): paste the VirusTotal API key, toggle automatic enrichment, adjust the rate limit and per-collection query cap, and manage the **whitelist and blacklist** (tabbed, with search, notes and one-click removal) — no terminal or `.env` editing required. The key is stored server-side only (`data/ti_config.json`, 0600) and never sent back to the browser.
- **Netstat triage view** in the job detail: a verdict summary bar (blacklisted / malicious / suspicious / clean / whitelisted / private), a findings table (indicator, VirusTotal verdict, detection ratio, owning process, one-click whitelist or blacklist with automatic re-run, link to the full VT report), plus filterable Connections and DNS-cache tables with blacklisted/malicious rows highlighted.
- **Machines** page: an inventory of every registered machine with its effective roles, automatic role confidence, OS/build, source (automatic or manual), status (online/stale/offline/never seen) and last-seen time. Filter by search text, roles (any-of), OS, host class, role source and status.
- **Machine detail** sheet: automatic roles and confidence, role revision/pending state, and a manual role editor. A manual set replaces the effective roles and is stored on the server and in the agent's local state; **Reset to automatic** clears it and makes the agent re-detect immediately.
- **Host role view** for `hostrole.v1`: the primary role, every scored role with its confidence and tier, and the evidence behind each one (expandable), including probe errors when a registry key or path could not be read.
- The token is kept only in the current tab's `sessionStorage`; every API call still uses the Bearer token. The UI has no build step and is embedded into the server binary via `go:embed`, so only the server needs rebuilding after asset changes.

## Threat Intelligence automation (netstat.v1)

When a `netstat.v1` job finishes (and auto-enrich is enabled, the default), the server enriches it in the background:

1. **Extraction** — every distinct remote address from the connection table and every cached DNS name becomes an indicator. IPs carry their owning processes, correlated domains and connection count; domains keep their record data.
2. **Filtering** — private/loopback/link-local/ULA/multicast addresses and internal hostnames (single-label names or names resolving only to private addresses) are recorded but never queried. Two operator-managed lists — **whitelist** (trusted) and **blacklist** (known bad) — accept exact IPs, CIDR networks, domains, and `*.wildcard` domains. Whitelisted values get verdict `whitelisted`, blacklisted values get `blacklisted`, and neither is sent to VirusTotal; **the blacklist wins if a value is on both lists** (the report records both matches so the conflict is visible). The default whitelist seeds common Windows OS noise (`*.microsoft.com`, `*.windowsupdate.com`, NCSI probes, `*.local`, `*.arpa`); the blacklist starts empty — it holds operator knowledge, never guesses.
3. **VirusTotal v3 queries** — public indicators are checked in triage priority (established connections first), inside the configured rate limit (default 4/min, the free-tier cap) and a per-collection budget (default 40 uncached queries). Verdicts: `malicious` (2+ engines), `suspicious` (1 engine), `clean`, `unrated` (unknown to VT), `whitelisted`/`blacklisted` (local lists, not queried), or `skipped` (budget/rate limit reached, or no API key configured).
4. **Reporting** — results are stored as a `ti_report` artifact next to the snapshot (the raw snapshot bytes are never modified, so its SHA-256 stays intact). Verdicts are cached on disk for 24 hours, so repeated indicators across collections cost no quota. Re-run the check at any time from the console — superseded reports stay on disk as evidence.

Without an API key the pipeline still runs and produces the classification-only report (verdict `skipped`); adding a key in the settings dialog and hitting **Re-run check** completes the triage. If the server restarts mid-run the job is marked `interrupted` rather than stuck at `running`.

## Flow and data format

1. The operator creates a job via `POST /v1/jobs` with the operator token; the server accepts an allowlisted host ID or, in wildcard mode, a host that has already checked in, plus catalog scenarios, with optional `since` in RFC3339 (e.g. `2026-10-24T00:00:00Z`).
2. The agent polls outbound via `GET /v1/agent/jobs/next` every `-interval` (default 5s), sends an inventory heartbeat to `POST /v1/agent/host` every `-heartbeat-interval` (default 1m), reports `skipped` when the host is not a web server and `needs_configuration` when the upload directory is missing, and never scans the whole host. Automatic role detection runs every `-role-interval` (default 1h) unless a manual override is active. `hostrole.v1` remains an on-demand evidence artifact; inventory roles are not a gate for other scenarios yet.
3. The agent reads files only from the configured paths (no symlinks), compares metadata before/after reading, computes SHA-256 over the exact bytes sent, then uploads evidence and metadata. The server verifies size and hash, stores `data/artifacts/<job-id>/<artifact-id>` and the manifest `data/jobs/<job-id>.json`.
4. The agent reports `completed`, `partial` or `failed` with a reason. A `running` job is retried by the agent after a restart; uploads with a known ID/hash are handled idempotently. `data/audit.jsonl` records job creation, viewing, artifact receipt, completion, downloads, TI runs, and settings/whitelist changes. The download API re-verifies the hash before serving any bytes.
5. For finished `netstat.v1` jobs the server runs the TI enrichment described above; the job manifest records the enrichment status (`ti_status`: `running` → `completed` / `partial` / `skipped` / `failed`) and reason.

Operator TI endpoints: `GET/PUT /v1/settings/ti`, `POST /v1/whitelist`, `DELETE /v1/whitelist/{id}`, `POST /v1/blacklist`, `DELETE /v1/blacklist/{id}`, and `POST /v1/jobs/{id}/ti` (re-run).

Inventory endpoints: `GET /v1/hosts`, `GET /v1/hosts/{id}`, `PUT /v1/hosts/{id}/roles`, `DELETE /v1/hosts/{id}/roles`; agents use `POST /v1/agent/host` for heartbeats and role assignment pickup.

## Front-end development

The console is a React 19 + TypeScript app (`web/`) built with Vite and embedded into the server binary via `go:embed`; it is served at `/`. Old `/next/*` bookmarks from the migration redirect to the same path at the root.

```bash
make web-install     # npm ci (runs in a Node 22 container)
make web-build       # build into internal/webui/dist, then rebuild the server
make web-dev         # Vite dev server on :5173 with /v1 proxied to :8080
make web-check       # typescript + ESLint + Stylelint + Vitest
```

- Dev-only component gallery: open `http://localhost:5173/?gallery` (light and dark).
- The bundle is written to `internal/webui/dist`; `make lab-up` also builds it inside Docker.
- Layout, conventions and recipes: [AGENTS.md](AGENTS.md).

Lab limits: at most 10 MiB per file, 256 files per job from the upload directory and 4 newest logs per job (260 artifacts total; older logs are dropped and noted in `reason`, which does not count as an error; exceeding the file limits is recorded as `partial`). Logs are captured whole when ≤ 10 MiB; **there is no `since`-based log tailoring yet**. Data on a running system may change before or after collection; the manifest describes the snapshot received and does not prove the state of the source at any earlier moment.

## Security and unimplemented features

- The lab currently runs **HTTP without TLS** (development phase): Bearer tokens and evidence travel in cleartext. Use it only on a trusted lab network and never expose the port to the Internet. Both binaries still support TLS (`-tls-cert`/`-tls-key` on the server, `-tls-ca` on the agent) to re-enable it later without code changes. Never put tokens in source code, committed configuration files or URLs. The VirusTotal key lives only in `data/ti_config.json` (0600, gitignored via `data/`); VirusTotal queries leave the **server** over HTTPS and carry only the filtered public indicators, never tokens or evidence.
- The server has one operator token and one agent token shared by every configured host: **no RBAC/multiple users, per-host agent identity enrollment or revocation, at-rest encryption, client certificates, per-investigator authentication, or tamper-evident signatures for manifests/audit logs**. In wildcard mode any token holder can register any valid hostname; use an isolated lab machine. This is not yet a legally complete chain-of-custody process. VirusTotal verdicts describe what third-party engines reported at query time and are **not** proof of maliciousness; the report records query time and cache provenance for exactly this reason.
- The agent runs elevated to read the chosen logs. The server sends no shell commands and cannot specify collection paths through a job. Symlinks (and junctions/reparse points on Windows) are skipped; upload locations are never auto-discovered; Nginx is not supported.
- On Windows the agent currently implements `netstat.v1`, `eventlog.v1`, `webshell.v1` (IIS) and `hostrole.v1`; scenarios such as `services.v1`/`autoruns.v1` and process-injection detection are not implemented. `hostrole.v1` detects Microsoft host roles only and reports configured roles, not live traffic.
- `deploy/` contains templates only: systemd units for the Linux server and `deploy/windows.md` for the Windows agent service. For a real deployment you must install the binary, create a dedicated user, place token files with `0600` permissions (e.g. `/etc/dfir-server.env`), adjust endpoints/paths and re-enable TLS. Nothing is auto-installed on end-user machines.
