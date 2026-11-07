package hostrole

import (
	"sort"
	"strings"
)

// defaultShares are present on stock Windows installations and must not turn
// every server into a file server. SYSVOL and NETLOGON belong to the domain
// controller role; they are evidence for AD DS, not for user file sharing.
var defaultShares = map[string]bool{
	"ADMIN$":   true,
	"IPC$":     true,
	"PRINT$":   true,
	"SYSVOL":   true,
	"NETLOGON": true,
}

// ParseShareValue extracts the configured path from one
// LanmanServer\Shares value. The value is a REG_MULTI_SZ of key=value lines
// (Path=, Remark=, Permissions=, ...); unknown and malformed lines are
// ignored.
func ParseShareValue(name string, lines []string) Share {
	share := Share{Name: strings.TrimSpace(name)}
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "path=") {
			share.Path = strings.TrimSpace(line[len("path="):])
			break
		}
	}
	return share
}

// IsDefaultShare reports whether a share is a stock administrative or domain
// share rather than an operator-created file share.
func IsDefaultShare(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if defaultShares[upper] {
		return true
	}
	// Single-drive administrative shares: C$, D$, ...
	if len(upper) == 2 && upper[1] == '$' && upper[0] >= 'A' && upper[0] <= 'Z' {
		return true
	}
	return false
}

// CustomShares returns the non-default shares, sorted by name. Hidden custom
// shares such as Finance$ are intentionally kept: they are common on real
// file servers.
func CustomShares(shares []Share) []Share {
	var custom []Share
	for _, share := range shares {
		if share.Name == "" || IsDefaultShare(share.Name) {
			continue
		}
		custom = append(custom, share)
	}
	sortShares(custom)
	return custom
}

func sortShares(shares []Share) {
	sort.SliceStable(shares, func(i, j int) bool {
		return strings.ToUpper(shares[i].Name) < strings.ToUpper(shares[j].Name)
	})
}

func hasShare(shares []Share, name string) bool {
	for _, share := range shares {
		if strings.EqualFold(share.Name, name) {
			return true
		}
	}
	return false
}
