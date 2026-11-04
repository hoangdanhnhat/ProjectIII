package ti

import "net/netip"

// IP classifications.
const (
	ClassPublic      = "public"
	ClassPrivate     = "private"  // non-routable address: never queried
	ClassInternal    = "internal" // hostname that only resolves internally
	ClassWhitelisted = "whitelisted"
	ClassBlacklisted = "blacklisted"
)

// IPClass reports whether an address is globally routable ("public") or
// local to the host or network ("private"): unspecified, loopback,
// RFC 1918, IPv6 unique local (fc00::/7), link-local, multicast, and
// broadcast addresses are all private. Private addresses are recorded in
// reports but never sent to VirusTotal.
func IPClass(addr netip.Addr) string {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return ClassPrivate
	}
	switch {
	case addr.IsUnspecified(),
		addr.IsLoopback(),
		addr.IsPrivate(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsMulticast(),
		addr.Is4() && addr == broadcastAddr():
		return ClassPrivate
	default:
		return ClassPublic
	}
}

func broadcastAddr() netip.Addr {
	b, _ := netip.ParseAddr("255.255.255.255")
	return b
}
