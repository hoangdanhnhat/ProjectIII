package netstat

import (
	"net/netip"
	"sort"
	"strings"
)

// Correlate attaches cached DNS names to connections: for every connection
// with a remote address, Domains lists the cache names that resolved to that
// address, following CNAME chains. It is a pure function over the snapshot
// so the logic is testable on any platform.
func Correlate(s *Snapshot) {
	ips := reverseResolve(s.DNSCache)
	for i := range s.Connections {
		c := &s.Connections[i]
		c.Domains = nil
		if c.RemoteAddr == "" {
			continue
		}
		addr, err := netip.ParseAddr(c.RemoteAddr)
		if err != nil {
			continue
		}
		if names, ok := ips[addr.Unmap()]; ok {
			c.Domains = names // sorted and deduplicated by reverseResolve
		}
	}
}

// ResolvedAddrs maps every cached name to the addresses it resolves to,
// following CNAME chains (cycle-safe). It is the name-oriented view of the
// same cache data Correlate uses in reverse; the threat-intel engine uses it
// to decide whether a cached name is an internal hostname.
func ResolvedAddrs(records []DNSRecord) map[string][]netip.Addr {
	cname, direct, names := cacheGraph(records)
	out := make(map[string][]netip.Addr, len(names))
	for name := range names {
		out[name] = resolveName(name, cname, direct, make(map[string]bool))
	}
	return out
}

// reverseResolve builds addr -> sorted domain names: a name contributes to
// every address its A/AAAA records hold directly plus everything reachable
// through its CNAME targets.
func reverseResolve(records []DNSRecord) map[netip.Addr][]string {
	cname, direct, names := cacheGraph(records)
	m := make(map[netip.Addr]map[string]bool)
	for name := range names {
		for _, addr := range resolveName(name, cname, direct, make(map[string]bool)) {
			set := m[addr]
			if set == nil {
				set = make(map[string]bool)
				m[addr] = set
			}
			set[name] = true
		}
	}
	out := make(map[netip.Addr][]string, len(m))
	for addr, set := range m {
		list := make([]string, 0, len(set))
		for name := range set {
			list = append(list, name)
		}
		sort.Strings(list)
		out[addr] = list
	}
	return out
}

// cacheGraph splits the records into CNAME edges, direct A/AAAA addresses,
// and the set of all names. Names are normalized defensively even though
// the collectors already emit them lowercased without a trailing dot.
func cacheGraph(records []DNSRecord) (cname map[string][]string, direct map[string][]netip.Addr, names map[string]bool) {
	cname = make(map[string][]string)
	direct = make(map[string][]netip.Addr)
	names = make(map[string]bool)
	for _, r := range records {
		name := normalizeName(r.Name)
		if name == "" {
			continue
		}
		names[name] = true
		switch r.Type {
		case "A", "AAAA":
			if addr, err := netip.ParseAddr(r.Data); err == nil {
				direct[name] = append(direct[name], addr.Unmap())
			}
		case "CNAME":
			target := normalizeName(r.Data)
			if target != "" {
				cname[name] = append(cname[name], target)
			}
		}
	}
	return cname, direct, names
}

// resolveName returns the addresses name resolves to: its direct A/AAAA
// data plus everything behind its CNAME targets. Cycles are cut by the
// visited set; chains are bounded by the number of distinct names.
func resolveName(name string, cname map[string][]string, direct map[string][]netip.Addr, visited map[string]bool) []netip.Addr {
	if visited[name] {
		return nil
	}
	visited[name] = true
	out := append([]netip.Addr(nil), direct[name]...)
	for _, target := range cname[name] {
		out = append(out, resolveName(target, cname, direct, visited)...)
	}
	return out
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
