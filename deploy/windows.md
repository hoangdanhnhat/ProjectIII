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

### Current single-host limit

The server is configured with **one** `-host-id` and **one** agent token, and rejects every
other `X-Host-ID`. To collect from a Windows and a Linux host at the same time you must
either:

- run two server instances with different `-listen`, `-data` and `-host-id` values, or
- extend the server with a per-host registry and per-agent credentials (not implemented in
  this prototype).

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
  -host-id win-lab `
  -uploads 'C:\inetpub\wwwroot\uploads' `
  -web-config 'C:\Windows\System32\inetsrv\config\applicationHost.config' `
  -web-logs 'C:\inetpub\logs\LogFiles\W3SVC*\*.log'
```

- `-uploads` is required: IIS has no standard upload directory, so the agent never guesses
  one. Without it the job returns `needs_configuration`.
- `-web-logs` accepts comma-separated paths or glob patterns. Globs are expanded and only
  the four newest matches are uploaded, so the server limit (260 artifacts = 256 uploads +
  4 logs) is never exceeded. IIS logs are sent with kind `iis_log`.
- `-apache-config` and `-apache-logs` are retained as aliases for `-web-config` and
  `-web-logs`.
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
nssm set dfir-agent AppParameters "-server http://dfir.example:8080 -host-id win-lab -uploads C:\inetpub\wwwroot\uploads -web-config C:\Windows\System32\inetsrv\config\applicationHost.config -web-logs C:\inetpub\logs\LogFiles\W3SVC*\*.log"
nssm set dfir-agent AppEnvironmentExtra "DFIR_AGENT_TOKEN=<agent-token>"
nssm set dfir-agent AppStdout "C:\dfir\agent.log"
nssm set dfir-agent AppStderr "C:\dfir\agent.err.log"
nssm set dfir-agent Start SERVICE_AUTO_START
nssm start dfir-agent
```

Protect the token: do not commit it, do not put it in the service command line (visible in
process listings), and restrict read access to the service configuration / environment
source. The lab prototype has no token file or Windows Credential Manager integration yet.
