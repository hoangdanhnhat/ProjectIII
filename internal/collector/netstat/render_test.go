package netstat

import (
	"testing"
	"time"
)

// TestRenderSortsAndOmitsEmpty runs on every platform: it verifies the pure
// rendering layer (sorting, deterministic output, omitempty semantics)
// without touching Windows APIs.
func TestRenderSortsAndOmitsEmpty(t *testing.T) {
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	snap := &Snapshot{
		SchemaVersion: 1,
		GeneratedAt:   at,
		Connections: []Connection{
			{Proto: "udp", LocalAddr: "0.0.0.0", LocalPort: 138, PID: 908, Process: "nbtsvc.exe"},
			{Proto: "tcp", LocalAddr: "0.0.0.0", LocalPort: 445, RemoteAddr: "0.0.0.0", RemotePort: 0, State: "LISTEN", PID: 4, Process: "System"},
			{Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 49152, RemoteAddr: "93.184.216.34", RemotePort: 443, State: "ESTABLISHED", PID: 4020, Process: "chrome.exe"},
			{Proto: "tcp", LocalAddr: "0.0.0.0", LocalPort: 80, RemoteAddr: "0.0.0.0", RemotePort: 0, State: "LISTEN", PID: 4, Process: "System"},
		},
	}
	data := string(Render(snap))
	want := `{
  "schema_version": 1,
  "generated_at": "2026-10-27T12:00:00Z",
  "connections": [
    {
      "proto": "tcp",
      "local_addr": "0.0.0.0",
      "local_port": 80,
      "remote_addr": "0.0.0.0",
      "remote_port": 0,
      "state": "LISTEN",
      "pid": 4,
      "process": "System"
    },
    {
      "proto": "tcp",
      "local_addr": "0.0.0.0",
      "local_port": 445,
      "remote_addr": "0.0.0.0",
      "remote_port": 0,
      "state": "LISTEN",
      "pid": 4,
      "process": "System"
    },
    {
      "proto": "tcp",
      "local_addr": "10.0.0.5",
      "local_port": 49152,
      "remote_addr": "93.184.216.34",
      "remote_port": 443,
      "state": "ESTABLISHED",
      "pid": 4020,
      "process": "chrome.exe"
    },
    {
      "proto": "udp",
      "local_addr": "0.0.0.0",
      "local_port": 138,
      "remote_addr": "",
      "remote_port": 0,
      "pid": 908,
      "process": "nbtsvc.exe"
    }
  ]
}`
	if data != want {
		t.Fatalf("render mismatch:\n%s", data)
	}
}
