//go:build linux || windows

package agent

import "testing"

func TestResolveHostID(t *testing.T) {
	id, err := resolveHostID("", "WIN-WEB01")
	if err != nil || id != "win-web01" {
		t.Fatalf("hostname fallback = %q, %v", id, err)
	}
	id, err = resolveHostID("DC01.", "ignored")
	if err != nil || id != "dc01" {
		t.Fatalf("explicit override = %q, %v", id, err)
	}
	if _, err := resolveHostID("", "bad host"); err == nil {
		t.Fatal("invalid hostname should return an error")
	}
}
