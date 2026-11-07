package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Host IDs are operator-visible keys and are also used as file names under
// data/hosts. The vocabulary is deliberately small and normalized to lower
// case so a machine hostname, a service flag and an API URL always agree.
var hostIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// NormalizeHostID trims, lowercases and validates a host ID. Hostnames are
// case-insensitive on Windows, so callers must use the returned value rather
// than the raw input.
func NormalizeHostID(raw string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(raw))
	id = strings.TrimRight(id, ".")
	if id == "" {
		return "", errors.New("host ID is empty")
	}
	if len(id) > 64 {
		return "", fmt.Errorf("host ID %q is longer than 64 characters", id)
	}
	if !hostIDPattern.MatchString(id) {
		return "", fmt.Errorf("host ID %q must match [a-z0-9][a-z0-9._-]{0,63}", id)
	}
	return id, nil
}

// ValidHostID reports whether NormalizeHostID would accept raw.
func ValidHostID(raw string) bool {
	_, err := NormalizeHostID(raw)
	return err == nil
}
