package netstat

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Snapshot is a point-in-time view of the host's TCP and UDP endpoints plus
// the DNS resolver cache captured at the same moment. The schema_version
// field lets analysis tooling detect format changes.
//
// Version 1 contained connections only. Version 2 adds the dns_cache array
// and per-connection domains correlated from that cache; both are omitted
// when empty, so version 1 artifacts remain valid input.
type Snapshot struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Connections   []Connection `json:"connections"`
	DNSCache      []DNSRecord  `json:"dns_cache,omitempty"`
}

// Connection describes one endpoint row. State is only set for TCP. Domains
// lists the cached DNS names that resolved to RemoteAddr (directly via
// A/AAAA records or through CNAME chains); it is empty for rows without a
// remote endpoint and for addresses absent from the cache.
type Connection struct {
	Proto      string   `json:"proto"` // tcp, tcp6, udp, udp6
	LocalAddr  string   `json:"local_addr"`
	LocalPort  int      `json:"local_port"`
	RemoteAddr string   `json:"remote_addr"`
	RemotePort int      `json:"remote_port"`
	State      string   `json:"state,omitempty"`
	PID        int      `json:"pid"`
	Process    string   `json:"process,omitempty"`
	Domains    []string `json:"domains,omitempty"`
}

// DNSRecord is one cached resolver entry relevant to correlation and
// threat-intel triage. Name is lowercased with no trailing dot; Data holds
// the address for A/AAAA records or the target name for CNAME.
type DNSRecord struct {
	Name string `json:"name"`
	Type string `json:"type"` // A, AAAA, CNAME
	TTL  int    `json:"ttl,omitempty"`
	Data string `json:"data"`
}

// Render serializes a snapshot as deterministic JSON: connections are sorted
// by proto, local endpoint, remote endpoint, then PID; DNS records by name,
// type, then data. Two snapshots of the same system state produce identical
// bytes.
func Render(s *Snapshot) []byte {
	sort.SliceStable(s.Connections, func(i, j int) bool {
		a, b := s.Connections[i], s.Connections[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.LocalPort != b.LocalPort {
			return a.LocalPort < b.LocalPort
		}
		if a.LocalAddr != b.LocalAddr {
			return a.LocalAddr < b.LocalAddr
		}
		if a.RemotePort != b.RemotePort {
			return a.RemotePort < b.RemotePort
		}
		if a.RemoteAddr != b.RemoteAddr {
			return a.RemoteAddr < b.RemoteAddr
		}
		return a.PID < b.PID
	})
	sort.SliceStable(s.DNSCache, func(i, j int) bool {
		a, b := s.DNSCache[i], s.DNSCache[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Data < b.Data
	})
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		// These types cannot fail to marshal; keep the failure loud anyway.
		return []byte(`{"error":"render failed"}`)
	}
	return data
}

// Parse decodes a rendered snapshot. Both schema versions this program has
// emitted are accepted; the threat-intel enrichment on the server reads
// agent artifacts through this function.
func Parse(data []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("netstat snapshot decode: %w", err)
	}
	if s.SchemaVersion < 1 || s.SchemaVersion > 2 {
		return nil, fmt.Errorf("netstat snapshot schema_version %d not supported", s.SchemaVersion)
	}
	return &s, nil
}
