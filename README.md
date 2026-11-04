# DFIR/CA evidence collector — server + Windows agent

Prototype consisting of an orchestrating server and a **Windows agent**, both written in Go. The server runs in Docker on a Linux machine (or anywhere Go builds); the agent runs on the Windows endpoint being monitored and connects **outbound only** — it never listens for inbound connections. Current scope: Windows 10/11 64-bit endpoints, scenarios `netstat.v1`, `eventlog.v1` and `webshell.v1`, plus automated **Threat Intelligence triage** of network connections via VirusTotal.

For `netstat.v1` the agent snapshots the TCP/UDP connection tables with owning processes **and the DNS client resolver cache** (read via `dnsapi.dll` with cache-only queries, generating zero network traffic; a `Get-DnsClientCache` fallback covers restricted hosts). Cached `A`/`AAAA`/`CNAME` records are correlated to connection remote addresses, so each connection records the domain name(s) it reached. When the job finishes, the server automatically triages the snapshot: public IPs and external domains (private/loopback/link-local addresses and whitelisted values are excluded) are checked against VirusTotal, and the verdicts land in the job as a `ti_report` artifact viewable in the web console. The result is **data for an investigation**, not an assertion of compromise.

For `webshell.v1` the agent checks the web server configuration file (IIS `applicationHost.config`) to confirm the host is a web server, reads the **explicitly configured upload directory** (IIS has no standard upload directory, so there is no default on Windows — without `-uploads` the job returns `needs_configuration` instead of scanning the drive) and collects files with script extensions (`.php`, `.phtml`, `.phar`, `.cgi`, `.pl`, `.py`, `.sh`, `.jsp`, `.aspx`). If the job carries a `since` timestamp, the agent also collects files modified after that moment, and it snapshots the newest IIS logs.

## What the agent collects on Windows

| Scenario | Artifact kinds | What it is |
| --- | --- | --- |
| `netstat.v1` | `netstat_snapshot`, `ti_report` | TCP/UDP connection table with owning processes + DNS client cache with domain correlation (schema v2); the server adds a VirusTotal triage report |
| `eventlog.v1` | `event_log` | Windows event log channels as schema-versioned JSON (one artifact per channel) |
| `webshell.v1` | `upload`, `iis_log` | Script-extension files from the configured upload directory + snapshots of the newest IIS logs |

## Quick start: Docker server + Windows agent

Requirements: a Linux machine with Docker + compose v2, `openssl` and `make`; a Windows 10/11 64-bit machine with PowerShell (Administrator for `eventlog.v1` with the `Security` channel); both on the same trusted network (the lab currently runs plain HTTP, see the security notes below).

```bash
make lab-init                          # once: random tokens in .env (gitignored)
make lab-up                            # build + start the server only
```

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
  -host-id lab-ubuntu `
  -interval 5s
```

`-host-id` must match the host ID the server authorizes (default `lab-ubuntu` in this lab; the server rejects every other ID). The agent is silent while idle (no job = HTTP 204, nothing printed).

Create a job from the Linux machine and wait for the result:

```bash
make lab-job SCENARIO=netstat.v1     # expect: completed, 1 artifact netstat_snapshot
make lab-job SCENARIO=eventlog.v1    # expect: completed, 1 artifact event_log per channel
```

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
.\bin\dfir-agent.exe -server http://dfir.example:8080 -host-id win-lab `
  -uploads 'C:\inetpub\wwwroot\uploads' `
  -web-config 'C:\Windows\System32\inetsrv\config\applicationHost.config' `
  -web-logs 'C:\inetpub\logs\LogFiles\W3SVC*\*.log'
```

Flags and behavior:

- `-uploads` **has no default on Windows** (IIS has no standard upload directory). If omitted or not an existing directory, a `webshell.v1` job returns `needs_configuration` instead of scanning the drive; the other scenarios are unaffected.
- `-web-config` defaults to `applicationHost.config` under `%SystemRoot%\System32\inetsrv\config`. It is used for role detection: without IIS the agent reports `skipped` by design. `-web-logs` defaults to the IIS log root (`%SystemDrive%\inetpub\logs\LogFiles\W3SVC*\*.log`).
- `-web-logs` accepts comma-separated paths or glob patterns; globs are expanded and only the **four newest** matches are uploaded (kind `iis_log`), so the server limit of 260 artifacts/job (256 uploads + 4 logs) is never exceeded. The current server accepts the `iis_log` kind; a server binary from before IIS support rejects it with HTTP 400, which the agent treats as a transport failure and retries forever — run the agent with `-web-logs ''` (files only) until the server is rebuilt.
- `-eventlog-channels` defaults to `System,Application`; add `Security` for a domain controller / incident value, which requires running as Administrator.
- `-apache-config` / `-apache-logs` are still accepted as aliases of `-web-config` / `-web-logs`.
- The agent reads the config and logs with the account it runs as; to read `applicationHost.config` and all site logs, run it as `LocalSystem` (or grant explicit read ACLs).
- Symlinks, junctions and other reparse points are rejected in every path component. On Windows the agent uses `os.Root` + `Lstat` per component; unlike `O_NOFOLLOW` on Linux, the check/open pair is not atomic, so a same-volume replacement in the race window is not fully prevented.
- It collects only files under the configured upload directory plus the configured log paths — it never scans a whole drive.
- One server instance authorizes exactly **one** `-host-id` and **one** agent token. To collect from several Windows machines at once, run additional server instances with different `-listen`, `-data` and `-host-id` values (per-host registry and per-agent credentials are not implemented).
- Installing the agent as a long-running service (NSSM/WinSW), and whether a separate server build is needed on Windows: see `deploy/windows.md` (TLS is deferred; the lab currently runs HTTP).

## Web console

Open `http://127.0.0.1:8080/` (or the server URL) and log in with `DFIR_OPERATOR_TOKEN`:

- View the collection list with status, duration and artifact count; refreshes automatically every 5 seconds.
- Create new jobs (`host_id`, scenario, optional `since`), open job details and download evidence with its SHA-256.
- **Threat Intel & Whitelist settings** (top-bar button): paste the VirusTotal API key, toggle automatic enrichment, adjust the rate limit and per-collection query cap, and manage the IP/CIDR/domain/wildcard whitelist — no terminal or `.env` editing required. The key is stored server-side only (`data/ti_config.json`, 0600) and never sent back to the browser.
- **Netstat triage view** in the job detail: a verdict summary bar (malicious / suspicious / clean / whitelisted / private), a findings table (indicator, VirusTotal verdict, detection ratio, owning process, one-click whitelisting with automatic re-run, link to the full VT report), plus filterable Connections and DNS-cache tables with malicious rows highlighted.
- The token is kept only in the current tab's `sessionStorage`; every API call still uses the Bearer token. The UI has no build step and is embedded into the server binary via `go:embed`, so only the server needs rebuilding after asset changes.

## Threat Intelligence automation (netstat.v1)

When a `netstat.v1` job finishes (and auto-enrich is enabled, the default), the server enriches it in the background:

1. **Extraction** — every distinct remote address from the connection table and every cached DNS name becomes an indicator. IPs carry their owning processes, correlated domains and connection count; domains keep their record data.
2. **Filtering** — private/loopback/link-local/ULA/multicast addresses and internal hostnames (single-label names or names resolving only to private addresses) are recorded but never queried. Whitelisted values (exact IP, CIDR, domain, or `*.wildcard`) are marked `whitelisted` and skipped — the default whitelist seeds common Windows OS noise (`*.microsoft.com`, `*.windowsupdate.com`, NCSI probes, `*.local`, `*.arpa`).
3. **VirusTotal v3 queries** — public indicators are checked in triage priority (established connections first), inside the configured rate limit (default 4/min, the free-tier cap) and a per-collection budget (default 40 uncached queries). Verdicts: `malicious` (2+ engines), `suspicious` (1 engine), `clean`, `unrated` (unknown to VT), or `skipped` (budget/rate limit reached, or no API key configured).
4. **Reporting** — results are stored as a `ti_report` artifact next to the snapshot (the raw snapshot bytes are never modified, so its SHA-256 stays intact). Verdicts are cached on disk for 24 hours, so repeated indicators across collections cost no quota. Re-run the check at any time from the console — superseded reports stay on disk as evidence.

Without an API key the pipeline still runs and produces the classification-only report (verdict `skipped`); adding a key in the settings dialog and hitting **Re-run check** completes the triage. If the server restarts mid-run the job is marked `interrupted` rather than stuck at `running`.

## Flow and data format

1. The operator creates a job via `POST /v1/jobs` with the operator token; the server accepts only the configured host ID and catalog scenarios, with optional `since` in RFC3339 (e.g. `2026-10-24T00:00:00Z`).
2. The agent polls outbound via `GET /v1/agent/jobs/next` every `-interval` (default 5s), reports `skipped` when the host is not a web server and `needs_configuration` when the upload directory is missing, and never scans the whole host.
3. The agent reads files only from the configured paths (no symlinks), compares metadata before/after reading, computes SHA-256 over the exact bytes sent, then uploads evidence and metadata. The server verifies size and hash, stores `data/artifacts/<job-id>/<artifact-id>` and the manifest `data/jobs/<job-id>.json`.
4. The agent reports `completed`, `partial` or `failed` with a reason. A `running` job is retried by the agent after a restart; uploads with a known ID/hash are handled idempotently. `data/audit.jsonl` records job creation, viewing, artifact receipt, completion, downloads, TI runs, and settings/whitelist changes. The download API re-verifies the hash before serving any bytes.
5. For finished `netstat.v1` jobs the server runs the TI enrichment described above; the job manifest records the enrichment status (`ti_status`: `running` → `completed` / `partial` / `skipped` / `failed`) and reason.

Operator TI endpoints: `GET/PUT /v1/settings/ti`, `POST /v1/whitelist`, `DELETE /v1/whitelist/{id}`, and `POST /v1/jobs/{id}/ti` (re-run).

Lab limits: at most 10 MiB per file, 256 files per job from the upload directory and 4 newest logs per job (260 artifacts total; older logs are dropped and noted in `reason`, which does not count as an error; exceeding the file limits is recorded as `partial`). Logs are captured whole when ≤ 10 MiB; **there is no `since`-based log tailoring yet**. Data on a running system may change before or after collection; the manifest describes the snapshot received and does not prove the state of the source at any earlier moment.

## Security and unimplemented features

- The lab currently runs **HTTP without TLS** (development phase): Bearer tokens and evidence travel in cleartext. Use it only on a trusted lab network and never expose the port to the Internet. Both binaries still support TLS (`-tls-cert`/`-tls-key` on the server, `-tls-ca` on the agent) to re-enable it later without code changes. Never put tokens in source code, committed configuration files or URLs. The VirusTotal key lives only in `data/ti_config.json` (0600, gitignored via `data/`); VirusTotal queries leave the **server** over HTTPS and carry only the filtered public indicators, never tokens or evidence.
- The server has one operator token and one agent token: **no RBAC/multiple users, agent identity enrollment or revocation, at-rest encryption, client certificates, per-investigator authentication, or tamper-evident signatures for manifests/audit logs**. Use an isolated lab machine; this is not yet a legally complete chain-of-custody process. VirusTotal verdicts describe what third-party engines reported at query time and are **not** proof of maliciousness; the report records query time and cache provenance for exactly this reason.
- The agent runs elevated to read the chosen logs. The server sends no shell commands and cannot specify collection paths through a job. Symlinks (and junctions/reparse points on Windows) are skipped; upload locations are never auto-discovered; Nginx is not supported.
- On Windows the agent currently implements `netstat.v1`, `eventlog.v1` and `webshell.v1` (IIS); scenarios such as `services.v1`/`autoruns.v1` and process-injection detection are not implemented.
- `deploy/` contains templates only: systemd units for the Linux server and `deploy/windows.md` for the Windows agent service. For a real deployment you must install the binary, create a dedicated user, place token files with `0600` permissions (e.g. `/etc/dfir-server.env`), adjust endpoints/paths and re-enable TLS. Nothing is auto-installed on end-user machines.
