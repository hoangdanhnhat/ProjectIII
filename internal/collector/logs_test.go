package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpandLogPatternsKeepsNewestAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	names := []string{}
	for i := 0; i < 6; i++ {
		name := filepath.Join(dir, fmt.Sprintf("log%d.log", i))
		if err := os.WriteFile(name, []byte("line"), 0600); err != nil {
			t.Fatal(err)
		}
		at := base.Add(-time.Duration(i) * time.Hour)
		if err := os.Chtimes(name, at, at); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	// The literal duplicate of the newest match must not consume a slot.
	got, dropped := ExpandLogPatterns([]string{filepath.Join(dir, "*.log"), names[0]}, 4)
	if dropped != 2 {
		t.Fatalf("dropped=%d, want 2", dropped)
	}
	if len(got) != 4 {
		t.Fatalf("len=%d, want 4: %v", len(got), got)
	}
	for i, want := range names[:4] {
		if got[i] != want {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want)
		}
	}
}

func TestExpandLogPatternsKeepsLiteralMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.log")
	got, dropped := ExpandLogPatterns([]string{"", "  ", filepath.Join(filepath.Dir(missing), "*.nomatch"), missing}, 4)
	if dropped != 0 || len(got) != 1 || got[0] != missing {
		t.Fatalf("got=%v dropped=%d, want [%q]", got, dropped, missing)
	}
}
