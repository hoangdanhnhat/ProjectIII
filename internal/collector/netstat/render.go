package netstat

import (
	"encoding/json"
	"sort"
	"time"
)

// Snapshot is a point-in-time view of the host's TCP and UDP endpoints. The
// schema_version field lets analysis tooling detect format changes.
type Snapshot struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Connections   []Connection `json:"connections"`
}

// Connection describes one endpoint row. State is only set for TCP.
type Connection struct {
	Proto      string `json:"proto"` // tcp, tcp6, udp, udp6
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state,omitempty"`
	PID        int    `json:"pid"`
	Process    string `json:"process,omitempty"`
}

// Render serializes a snapshot as deterministic JSON: connections are sorted
// by proto, local endpoint, remote endpoint, then PID, so two snapshots of
// the same system state produce identical bytes.
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
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		// These types cannot fail to marshal; keep the failure loud anyway.
		return []byte(`{"error":"render failed"}`)
	}
	return data
}
