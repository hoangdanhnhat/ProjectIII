package netstat

import (
	"reflect"
	"testing"
)

// TestCorrelateFollowsCNAMEChains verifies the IP -> domain mapping across
// a CNAME chain: both the queried name and the canonical name appear on the
// connection.
func TestCorrelateFollowsCNAMEChains(t *testing.T) {
	s := &Snapshot{
		Connections: []Connection{
			{Proto: "tcp", RemoteAddr: "93.184.216.34", RemotePort: 443, PID: 4020},
			{Proto: "tcp", RemoteAddr: "10.0.0.9", RemotePort: 445, PID: 4},
			{Proto: "udp", LocalAddr: "0.0.0.0", LocalPort: 138, PID: 908},
		},
		DNSCache: []DNSRecord{
			{Name: "portal.example.com", Type: "CNAME", Data: "cdn.example.net"},
			{Name: "cdn.example.net", Type: "A", Data: "93.184.216.34"},
			{Name: "intranet.corp", Type: "A", Data: "10.0.0.9"},
		},
	}
	Correlate(s)
	want := []string{"cdn.example.net", "portal.example.com"}
	if got := s.Connections[0].Domains; !reflect.DeepEqual(got, want) {
		t.Fatalf("chained domains = %v, want %v", got, want)
	}
	if got := s.Connections[1].Domains; !reflect.DeepEqual(got, []string{"intranet.corp"}) {
		t.Fatalf("private-IP domains = %v", got)
	}
	if got := s.Connections[2].Domains; got != nil {
		t.Fatalf("UDP row without remote got domains %v", got)
	}
}

// TestCorrelateHandlesCyclesAndIPv6 guards against cache oddities: a CNAME
// cycle must not hang, and IPv6 (including 4-in-6) matches AAAA data.
func TestCorrelateHandlesCyclesAndIPv6(t *testing.T) {
	s := &Snapshot{
		Connections: []Connection{
			{Proto: "tcp6", RemoteAddr: "2606:2800:220:1:248:1893:25c8:1946", RemotePort: 443, PID: 1},
			{Proto: "tcp", RemoteAddr: "::ffff:93.184.216.34", RemotePort: 80, PID: 2},
		},
		DNSCache: []DNSRecord{
			{Name: "a.example", Type: "CNAME", Data: "b.example"},
			{Name: "b.example", Type: "CNAME", Data: "a.example"}, // cycle
			{Name: "v6.example", Type: "AAAA", Data: "2606:2800:220:1:248:1893:25c8:1946"},
			{Name: "legacy.example", Type: "A", Data: "93.184.216.34"},
		},
	}
	Correlate(s)
	if got := s.Connections[0].Domains; !reflect.DeepEqual(got, []string{"v6.example"}) {
		t.Fatalf("ipv6 domains = %v", got)
	}
	if got := s.Connections[1].Domains; !reflect.DeepEqual(got, []string{"legacy.example"}) {
		t.Fatalf("4-in-6 domains = %v", got)
	}
}

// TestResolvedAddrs verifies the name -> addresses view used by the
// threat-intel engine to classify internal hostnames.
func TestResolvedAddrs(t *testing.T) {
	records := []DNSRecord{
		{Name: "portal.example.com", Type: "CNAME", Data: "cdn.example.net"},
		{Name: "cdn.example.net", Type: "A", Data: "93.184.216.34"},
		{Name: "intranet.corp", Type: "A", Data: "10.0.0.9"},
	}
	resolved := ResolvedAddrs(records)
	if got := len(resolved["portal.example.com"]); got != 1 {
		t.Fatalf("portal resolves to %d addresses, want 1", got)
	}
	if got := len(resolved["intranet.corp"]); got != 1 {
		t.Fatalf("intranet resolves to %d addresses, want 1", got)
	}
	if got := len(resolved["nothing.example"]); got != 0 {
		t.Fatalf("unknown name resolves to %d addresses", got)
	}
}
