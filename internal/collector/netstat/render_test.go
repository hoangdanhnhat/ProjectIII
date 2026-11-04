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
		SchemaVersion: 2,
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
  "schema_version": 2,
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

// TestRenderWithDNSCacheAndDomains covers the version 2 additions: the
// dns_cache array, per-connection domains, and their deterministic sort.
func TestRenderWithDNSCacheAndDomains(t *testing.T) {
	at := time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC)
	snap := &Snapshot{
		SchemaVersion: 2,
		GeneratedAt:   at,
		Connections: []Connection{
			{
				Proto: "tcp", LocalAddr: "10.0.0.5", LocalPort: 51000,
				RemoteAddr: "93.184.216.34", RemotePort: 443,
				State: "ESTABLISHED", PID: 4020, Process: "chrome.exe",
				Domains: []string{"cdn.example.net", "portal.example.com"},
			},
		},
		DNSCache: []DNSRecord{
			{Name: "portal.example.com", Type: "CNAME", TTL: 47, Data: "cdn.example.net"},
			{Name: "cdn.example.net", Type: "A", TTL: 47, Data: "93.184.216.34"},
		},
	}
	data := string(Render(snap))
	want := `{
  "schema_version": 2,
  "generated_at": "2026-11-01T09:30:00Z",
  "connections": [
    {
      "proto": "tcp",
      "local_addr": "10.0.0.5",
      "local_port": 51000,
      "remote_addr": "93.184.216.34",
      "remote_port": 443,
      "state": "ESTABLISHED",
      "pid": 4020,
      "process": "chrome.exe",
      "domains": [
        "cdn.example.net",
        "portal.example.com"
      ]
    }
  ],
  "dns_cache": [
    {
      "name": "cdn.example.net",
      "type": "A",
      "ttl": 47,
      "data": "93.184.216.34"
    },
    {
      "name": "portal.example.com",
      "type": "CNAME",
      "ttl": 47,
      "data": "cdn.example.net"
    }
  ]
}`
	if data != want {
		t.Fatalf("render mismatch:\n%s", data)
	}
}

// TestParseRoundTrip verifies Parse accepts what Render emits, including a
// version 1 artifact with no DNS fields.
func TestParseRoundTrip(t *testing.T) {
	snap := &Snapshot{
		SchemaVersion: 2,
		GeneratedAt:   time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		Connections:   []Connection{{Proto: "tcp", LocalAddr: "1.2.3.4", LocalPort: 1, RemoteAddr: "5.6.7.8", RemotePort: 443, PID: 1}},
		DNSCache:      []DNSRecord{{Name: "a.example", Type: "A", Data: "5.6.7.8"}},
	}
	parsed, err := Parse(Render(snap))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Connections) != 1 || len(parsed.DNSCache) != 1 {
		t.Fatalf("round trip lost data: %+v", parsed)
	}
	v1 := `{"schema_version":1,"generated_at":"2026-10-24T00:00:00Z","connections":[{"proto":"tcp","local_addr":"0.0.0.0","local_port":80,"remote_addr":"1.2.3.4","remote_port":80,"pid":4}]}`
	if _, err := Parse([]byte(v1)); err != nil {
		t.Fatalf("version 1 artifact rejected: %v", err)
	}
	if _, err := Parse([]byte(`{"schema_version":99}`)); err == nil {
		t.Fatal("unknown schema_version accepted")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}
