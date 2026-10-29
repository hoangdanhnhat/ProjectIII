//go:build !windows

package netstat

import "errors"

// snapshot is only implemented on Windows today (a Linux /proc parser is
// planned). The registry filters unsupported platforms before Collect runs,
// so this stub only keeps non-Windows builds compiling.
func snapshot() (*Snapshot, error) {
	return nil, errors.New("netstat snapshot not implemented on this platform")
}
