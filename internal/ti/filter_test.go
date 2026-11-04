package ti

import (
	"net/netip"
	"testing"
)

func TestIPClass(t *testing.T) {
	for _, tc := range []struct {
		addr, want string
	}{
		{"8.8.8.8", ClassPublic},
		{"1.1.1.1", ClassPublic},
		{"93.184.216.34", ClassPublic},
		{"10.0.0.1", ClassPrivate},
		{"172.16.0.1", ClassPrivate},
		{"172.31.255.255", ClassPrivate},
		{"192.168.1.1", ClassPrivate},
		{"127.0.0.1", ClassPrivate},
		{"169.254.100.7", ClassPrivate},
		{"0.0.0.0", ClassPrivate},
		{"255.255.255.255", ClassPrivate},
		{"224.0.0.1", ClassPrivate},
		{"::1", ClassPrivate},
		{"fe80::1", ClassPrivate},
		{"fc00::1234", ClassPrivate},
		{"fdab::1", ClassPrivate},
		{"ff02::1", ClassPrivate},
		{"2606:2800:220:1:248:1893:25c8:1946", ClassPublic},
		{"::ffff:8.8.8.8", ClassPublic}, // 4-in-6 unmapped to public IPv4
		{"::ffff:10.0.0.1", ClassPrivate},
	} {
		addr, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.addr, err)
		}
		if got := IPClass(addr); got != tc.want {
			t.Errorf("IPClass(%s) = %s, want %s", tc.addr, got, tc.want)
		}
	}
}
