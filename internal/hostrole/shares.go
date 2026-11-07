package hostrole

import (
	"sort"
	"strings"
)

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
