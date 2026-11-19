# DFIR collector on Windows

## Do you need a separate server program?

No. `cmd/dfir-server` is plain Go (`net/http`, `os`, `path/filepath`) and cross-compiles unchanged:

```powershell
go build -o bin\dfir-server.exe .\cmd\dfir-server
```

The only server change needed for Windows agents is that artifact uploads accept the
`iis_log` kind in addition to `upload` and `apache_log`. Scenario IDs stay the same
(`webshell.v1`). Rebuild the server before pointing a Windows agent at it; an old server
rejects `iis_log` with HTTP 400, which the agent treats as a transport failure, so the job
stays `running` and is retried. Until the server is updated, run the agent with
`-web-logs ''` to collect files only.

Recommended topology:

```text
Windows endpoint (dfir-agent.exe, outbound HTTP for now)  ->  Linux/Windows server (dfir-server)
```

The endpoint never listens for inbound connections. Give the agent
`-server http://<server>:8080` — plain HTTP is the current development setup, so
tokens and evidence are not encrypted on the wire; keep this on a trusted lab
network. HTTPS still works (`-server https://...` plus `-tls-ca`) when TLS is
wired back in.

### Multiple managed hosts

The server accepts `-hosts '*'` (the lab default) to authorize any valid machine hostname
presented with the shared agent token, or a comma-separated
`-hosts lab-ubuntu,win-web01,win-dc01` allowlist. The agent uses the machine hostname,
lowercased, when `-host-id` is omitted; pass `-host-id` only to override a collision or
keep a stable ID after a rename. This is a lab compromise: any token holder can register
any valid hostname in wildcard mode. Per-host tokens, enrollment and revocation are not
implemented in this prototype.

Each agent also sends an inventory heartbeat (`POST /v1/agent/host`) every minute and
refreshes its roles hourly. The role cache lives at
`%ProgramData%\dfir-agent\host_state.json` by default; set `-state` to move it. A manual
override in the console replaces the automatic role set and stops detection until reset.

### Running the server on Windows

- Plain HTTP is allowed for now (no `-tls-cert`/`-tls-key` needed); it logs a warning
  because credentials travel unencrypted. Optionally pass both TLS flags to serve HTTPS.
- `0700` directory modes have no effect on Windows; restrict `data\` and `audit.jsonl` with
  ACLs (`icacls data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F"` and grant the service
  account read/write as needed).
- Run it under a service wrapper (NSSM or WinSW) instead of a console window.
- `./data` resolves relative to the working directory, which for a service is usually
  `C:\Windows\System32`; pass an absolute `-data` path.

## Build the agent

```powershell
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -o bin\dfir-agent.exe .\cmd\dfir-agent
```

Requires Go 1.24+ (the Windows secure-file helper uses `os.Root`). Build **amd64** even on
64-bit Windows. A 32-bit process sees `System32` through WOW64 redirection and would read
the wrong IIS configuration and logs.

## Run

```powershell
$env:DFIR_AGENT_TOKEN = '<agent-token>'
.\bin\dfir-agent.exe `
  -server http://dfir.example:8080 `
  -state 'C:\ProgramData\dfir-agent\host_state.json' `
  -uploads 'C:\inetpub\wwwroot\uploads' `
  -web-config 'C:\Windows\System32\inetsrv\config\applicationHost.config' `
  -web-logs 'C:\inetpub\logs\LogFiles\W3SVC*\*.log'
```

- `-uploads` is required: IIS has no standard upload directory, so the agent never guesses
  one. Without it the job returns `needs_configuration`.
- `-state` sets the local role cache. `-heartbeat-interval` defaults to `1m` and
  `-role-interval` to `1h`. Run the agent as `LocalSystem` for full registry coverage.
- `-web-logs` accepts comma-separated paths or glob patterns. Globs are expanded and only
  the four newest matches are uploaded, so the server limit (260 artifacts = 256 uploads +
  4 logs) is never exceeded. IIS logs are sent with kind `iis_log`.
- `-apache-config` and `-apache-logs` are retained as aliases for `-web-config` and
  `-web-logs`.
- `memory.v1` is opt-in and needs three flags: `-memory-tool` (absolute path to an
  operator-provided WinPmem binary), `-memory-tool-sha256` (its pinned SHA-256) and
  `-memory-out` (an existing staging directory). The agent never downloads the tool,
  verifies the digest at startup and before every capture, refuses to run without an
  elevated token, and requires free space of at least physical RAM + 256 MiB. WinPmem 4.x
  returns 1 after a completed capture and -1 on failure; the `winpmem` profile accepts
  that convention and records the code in the manifest. Add
  `-memory-tool-name winpmem-physical` (or `winpmem`/`winpmem-mini`) if the executable name is
  ambiguous, raise
  `-memory-max-bytes` and the server's `-max-memory-image` together for hosts above 16 GiB
  of RAM, and use `-memory-keep` only when you deliberately want a second copy of the image
  on the endpoint. A failed run still uploads a `memory_manifest` with the tool exit code
  and stderr tail. Once a valid image is uploaded, the server runs Volatility 3 analysis
  automatically (Docker image) and stores JSONL plugin outputs plus a report.
- The agent reads the config/logs with the account it runs as. To read
  `applicationHost.config` and all site logs, run it as `LocalSystem` (or grant explicit
  read ACLs).
- The collector only reads files under the configured upload directory plus the configured
  log paths. It skips symlinks, junctions, and other reparse points and never scans a whole
  drive.

## Install as a service

NSSM is convenient for a lab; WinSW is an alternative. Example with NSSM:

```powershell
nssm install dfir-agent "C:\dfir\dfir-agent.exe"
nssm set dfir-agent AppParameters "-server http://dfir.example:8080 -state C:\ProgramData\dfir-agent\host_state.json -uploads C:\inetpub\wwwroot\uploads -web-config C:\Windows\System32\inetsrv\config\applicationHost.config -web-logs C:\inetpub\logs\LogFiles\W3SVC*\*.log"
nssm set dfir-agent AppEnvironmentExtra "DFIR_AGENT_TOKEN=<agent-token>"
nssm set dfir-agent AppStdout "C:\dfir\agent.log"
nssm set dfir-agent AppStderr "C:\dfir\agent.err.log"
nssm set dfir-agent Start SERVICE_AUTO_START
nssm start dfir-agent
```

Protect the token: do not commit it, do not put it in the service command line (visible in
process listings), and restrict read access to the service configuration / environment
source. The lab prototype has no token file or Windows Credential Manager integration yet.
