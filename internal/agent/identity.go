package agent

import (
	"fmt"
	"os"
	"strings"

	"example.com/dfir-collector/internal/protocol"
)

// ResolveHostID returns the explicit host ID when provided, otherwise the
// machine hostname normalized to the shared host-ID vocabulary. The explicit
// flag remains available for name collisions and renames.
func ResolveHostID(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return protocol.NormalizeHostID(explicit)
	}
	name, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("read machine hostname: %w", err)
	}
	return resolveHostID("", name)
}

func resolveHostID(explicit, hostname string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return protocol.NormalizeHostID(explicit)
	}
	id, err := protocol.NormalizeHostID(hostname)
	if err != nil {
		return "", fmt.Errorf("machine hostname %q is not a valid host ID (%v); pass -host-id explicitly", hostname, err)
	}
	return id, nil
}
