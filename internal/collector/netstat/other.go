//go:build !windows

package netstat

import (
	"context"
	"errors"
)

// snapshot is only implemented on Windows today (a Linux /proc parser is
// planned). The registry filters unsupported platforms before Collect runs,
// so these stubs only keep non-Windows builds compiling.
func snapshot() (*Snapshot, error) {
	return nil, errors.New("netstat snapshot not implemented on this platform")
}

func dnsCacheRecords(ctx context.Context) ([]DNSRecord, error) {
	return nil, errors.New("DNS client cache collection is only implemented on Windows")
}
