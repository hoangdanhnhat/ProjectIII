# Setup guide — DFIR evidence collector (server + Windows agent)

End-to-end instructions for going from a fresh clone to a working lab:
a coordination server in Docker on a Linux machine, a collector agent on a
Windows endpoint, and automated VirusTotal triage of network connections —
all configurable from the web console, no terminal configuration needed
after the initial setup.

```text
Windows endpoint (dfir-agent.exe)                Linux machine (Docker)
─────────────────────────────────                ──────────────────────
collects connections + DNS cache                 dfir-server  (console :8080)
polls OUTBOUND every 5s  ────── HTTP ──────────▶ stores evidence in ./data/
never listens for inbound                        enriches public IPs/domains
                                                 via VirusTotal (server-side)
```

The endpoint needs **no inbound ports** and **no internet access** — only the
VirusTotal queries leave the server, over HTTPS.

## Requirements

| Machine | Needs |
| --- | --- |
| Linux (server) | Docker + compose v2, `openssl`, `make`, internet access during the image build and for VirusTotal queries |
| Windows (endpoint) | Windows 10/11 64-bit, PowerShell; Administrator only if you want the `Security` event log channel or a service install |
| Network | Both machines on the same trusted network (the lab runs plain HTTP — see security notes at the end) |

## Step 0 — get the code

```bash
git clone https://github.com/hoangdanhnhat/ProjectIII.git
cd ProjectIII
```

## Step 1 — start the coordination server

```bash
make lab-init     # creates .env with two random tokens (safe to re-run)
make lab-up       # builds and starts the dfir-server container
```

What this did:

- `.env` (gitignored) now holds `DFIR_OPERATOR_TOKEN` (console/API access)
  and `DFIR_AGENT_TOKEN` (what the Windows agent presents). Keep both secret.
- Evidence, job manifests, the TI settings, the whitelist and the verdict
  cache live in `./data/` on the Linux machine (gitignored as well).
- The console is at `http://localhost:8080/` (LAN: `http://<linux-ip>:8080/`).

Port already in use? Add `DFIR_CONSOLE_PORT=18080` to `.env` and re-run
`make lab-up`.

> Do **not** run `make lab-up-web` in this setup: the optional Linux `web`
> container shares the server's single host ID and would steal jobs from
> your Windows agent (Windows scenarios would come back `skipped`).

## Step 2 — build the Windows agent

Option A — cross-compile on the Linux machine (no Go install needed; the
container handles the toolchain, `chown` keeps the file owned by you):

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.24 sh -c \
  "go build -trimpath -o /src/bin/dfir-agent-windows.exe ./cmd/dfir-agent && chown $(id -u):$(id -g) /src/bin/dfir-agent-windows.exe"
sha256sum bin/dfir-agent-windows.exe    # note this hash
```

Option B — build on the Windows machine (requires Go 1.24+):

```powershell
git clone https://github.com/hoangdanhnhat/ProjectIII.git
cd ProjectIII
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -o C:\dfir\dfir-agent.exe .\cmd\dfir-agent
```

Always build **amd64**, even on 64-bit Windows: a 32-bit process sees
`System32` through WOW64 redirection and would read the wrong IIS
configuration and logs.

## Step 3 — deploy the agent on the Windows machine

Copy `bin/dfir-agent-windows.exe` to the endpoint (SMB, RDP clipboard, scp).
For a quick LAN transfer from Linux:

```bash
mkdir -p /tmp/dfir-agent-download
cp bin/dfir-agent-windows.exe /tmp/dfir-agent-download/dfir-agent.exe
python3 -m http.server 8000 --bind 0.0.0.0 --directory /tmp/dfir-agent-download
```

```powershell
# on Windows: download, then confirm it is the current build
curl.exe -o C:\dfir\dfir-agent.exe http://<linux-ip>:8000/dfir-agent.exe
Get-FileHash C:\dfir\dfir-agent.exe -Algorithm SHA256   # must match the Linux hash
```

Get the agent token from the Linux machine (`grep DFIR_AGENT_TOKEN .env`)
and run the agent in a PowerShell window:

```powershell
$env:DFIR_AGENT_TOKEN = '<DFIR_AGENT_TOKEN from .env>'
C:\dfir\dfir-agent.exe `
  -server http://<linux-ip>:8080 `
  -host-id lab-ubuntu `
  -interval 5s
```

- `-host-id` **must** be `lab-ubuntu` (the host ID the server authorizes).
- The agent is silent while idle — no output means no jobs yet, which is
  correct. It never opens a port for inbound connections.
- Optional flags for the other scenarios:
  - `-eventlog-channels 'System,Application,Security'` — `Security`
    requires an Administrator PowerShell.
  - `-uploads 'C:\inetpub\wwwroot\uploads'` — needed for `webshell.v1`
    (IIS has no standard upload directory; without the flag that scenario
    reports `needs_configuration`, the others are unaffected).

Connectivity check from Windows if nothing happens:
`Test-NetConnection <linux-ip> -Port 8080`.

## Step 4 — configure Threat Intel (web console, no terminal)

1. Open `http://<linux-ip>:8080/` and log in with `DFIR_OPERATOR_TOKEN`
   (from `.env` on the Linux machine).
2. Click **Threat Intel** in the top bar.
3. Paste your **VirusTotal API key** (free key: virustotal.com → profile →
   API key) and press **Save settings**. The key is stored only on the
   server (`data/ti_config.json`, mode 0600) and never sent back to the
   browser.
4. Review the **whitelist**: entries (IP, CIDR, domain, `*.wildcard`) are
   recorded in reports but never sent to VirusTotal. Sensible Windows OS
   noise (microsoft.com, windowsupdate.com, NCSI probes, `*.local`,
   `*.arpa`) is pre-seeded — add or remove entries freely.
5. Defaults are fine to start: auto-enrich **on**, 4 requests/minute
   (VirusTotal free tier), max 40 checks per collection. Verdicts are
   cached for 24 hours, so repeated indicators cost no quota.

No key yet? The pipeline still runs and classifies everything (public /
private / whitelisted); verdicts show as *skipped* until you add a key and
press **Re-run check**.

## Step 5 — run your first collection

From the Linux machine:

```bash
make lab-job SCENARIO=netstat.v1
```

Expect `status: completed` with a `netstat_snapshot` artifact. The server
then enriches it automatically — open the job in the console and you get:

- a **verdict summary** (malicious / suspicious / clean / whitelisted / private),
- the **Findings** table: every public IP and domain with its VirusTotal
  verdict, detection ratio (`7/92`), the owning process (`chrome.exe (4020)`),
  correlated domains, a link to the full VT report, and a one-click
  *whitelist + re-run* button per row,
- **Connections** and **DNS cache** tabs with a filter box; rows linked to
  malicious indicators are highlighted.

Try the other scenarios the same way:

```bash
make lab-job SCENARIO=eventlog.v1    # one event_log artifact per channel
make lab-job SCENARIO=webshell.v1    # requires -uploads on the agent (IIS)
```

Download evidence from the console, or verify hashes from the shell:

```bash
make lab-status        # list jobs, newest first
set -a; . ./.env; set +a
curl -sS -H "Authorization: Bearer $DFIR_OPERATOR_TOKEN" \
  http://localhost:8080/v1/jobs/<job-id>/artifacts/<artifact-id> -o evidence.bin
sha256sum evidence.bin  # must match "sha256" in the job JSON
```

## Step 6 (optional) — run the agent as a Windows service

So collection survives reboots and logout, install it under NSSM (WinSW
works too):

```powershell
nssm install dfir-agent "C:\dfir\dfir-agent.exe"
nssm set dfir-agent AppParameters "-server http://<linux-ip>:8080 -host-id lab-ubuntu -eventlog-channels System,Application,Security"
nssm set dfir-agent AppEnvironmentExtra "DFIR_AGENT_TOKEN=<agent-token>"
nssm set dfir-agent AppStdout "C:\dfir\agent.log"
nssm set dfir-agent AppStderr "C:\dfir\agent.err.log"
nssm set dfir-agent Start SERVICE_AUTO_START
nssm start dfir-agent
```

The token must go in the service environment, never in the command line
(arguments are visible in process listings).

## Updating an existing deployment

Both binaries must move together for new features (schema and API changes):

```bash
git pull
make lab-up                                        # rebuilds the server container
# rebuild + recopy bin/dfir-agent-windows.exe to the Windows machine
# (verify the new SHA-256), then restart the agent/service
```

Old jobs and evidence in `./data/` are untouched by an update.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Job stuck `queued` | No agent is polling. Check the agent window on Windows and `Test-NetConnection <linux-ip> -Port 8080`. |
| Agent logs `poll: HTTP 401` | Agent token mismatch — use the exact `DFIR_AGENT_TOKEN` from `.env`. |
| Agent logs `poll: HTTP 400 unsupported host` | `-host-id` is not `lab-ubuntu`. |
| Agent prints `HTTP allowed only on loopback` and exits | The exe on that machine predates the current build — recopy it and check the SHA-256. |
| `webshell.v1` returns `needs_configuration` | `-uploads` missing or not an existing directory (IIS has no default). |
| `webshell.v1` returns `skipped` | No IIS on that machine — by design (role detection via `applicationHost.config`). |
| `eventlog.v1` returns `partial` with access denied | The `Security` channel needs an Administrator agent. |
| Job `ti_status` is `skipped` | No VirusTotal key configured — add it in the console and press **Re-run check**. |
| Job `ti_status` is `partial` | Some VT queries failed (invalid key or HTTP 429) — the reason on the job names the error; wait a minute and re-run. |
| Windows scenarios return `skipped ... not implemented on linux` | The optional Linux `web` container is running and claimed the job: `docker compose stop web`. |
| Port 8080 already in use | Set `DFIR_CONSOLE_PORT=18080` in `.env`, then `make lab-up` again. |
| Console unreachable from Windows | Check the Linux firewall and use the LAN IP, not `localhost`. |

## Teardown and reset

```bash
make lab-down     # stop the lab, keep ./data/ and .env
make lab-clean    # stop and delete ./data/, .env and leftover certs (full reset)
```

## Security notes (lab scope)

- The lab runs **plain HTTP**: tokens and evidence are unencrypted on the
  wire. Keep it on a trusted network and never expose port 8080 to the
  Internet. Both binaries still support TLS (`-tls-cert`/`-tls-key` on the
  server, `-tls-ca` on the agent) for later.
- One operator token, one agent token, one authorized host ID per server
  instance. Multi-user/RBAC is out of scope for the prototype.
- The VirusTotal key never leaves the server; queries carry only the
  filtered public indicators. Verdicts are third-party opinions at query
  time, not proof of compromise — the report records query time and cache
  provenance for that reason.
