//go:build linux || windows

package webshell

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/collector/sinktest"
	"example.com/dfir-collector/internal/protocol"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCollectSelectsScriptFiles(t *testing.T) {
	dir := t.TempDir()
	uploads := filepath.Join(dir, "uploads")
	if err := os.Mkdir(uploads, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "apache2.conf")
	writeFile(t, config, "# lab Apache config")
	writeFile(t, filepath.Join(uploads, "example.PHP"), "benign php fixture")
	writeFile(t, filepath.Join(uploads, "photo.jpg"), "normal image")
	if err := os.Symlink(config, filepath.Join(uploads, "escape.php")); err != nil {
		// Windows only allows symlinks for elevated processes or with
		// Developer Mode; the escape fixture is optional there.
		t.Logf("symlink fixture skipped: %v", err)
	}
	rec := &sinktest.Recorded{}
	c := New(Options{UploadsDir: uploads, WebConfig: config})
	if err := c.Collect(context.Background(), &protocol.Job{ID: "fixture", Scenario: protocol.ScenarioWebshell}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Files) != 1 {
		t.Fatalf("files: %+v", rec.Files)
	}
	got := rec.Files[0]
	if got.Kind != protocol.KindUpload || got.Path != filepath.Join(uploads, "example.PHP") ||
		got.Reason != "script extension in upload directory" {
		t.Fatalf("unexpected artifact call: %+v", got)
	}
	if len(rec.Problems) != 0 {
		t.Fatalf("problems: %v", rec.Problems)
	}
}

func TestSinceSelectsRecentlyModifiedNonScript(t *testing.T) {
	dir := t.TempDir()
	uploads := filepath.Join(dir, "uploads")
	if err := os.Mkdir(uploads, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "apache.conf")
	writeFile(t, config, "ok")
	writeFile(t, filepath.Join(uploads, "a.txt"), "recent")
	writeFile(t, filepath.Join(uploads, "old.txt"), "old")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(uploads, "old.txt"), old, old); err != nil {
		t.Fatal(err)
	}
	since := time.Now().Add(-time.Hour)
	rec := &sinktest.Recorded{}
	c := New(Options{UploadsDir: uploads, WebConfig: config})
	job := &protocol.Job{ID: "recent", Since: &since}
	if err := c.Collect(context.Background(), job, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Files) != 1 || rec.Files[0].Path != filepath.Join(uploads, "a.txt") ||
		rec.Files[0].Reason != "modified since requested time" {
		t.Fatalf("since selection: %+v", rec.Files)
	}
}

func TestSkipsWithoutWebConfig(t *testing.T) {
	dir := t.TempDir()
	uploads := filepath.Join(dir, "uploads")
	if err := os.Mkdir(uploads, 0700); err != nil {
		t.Fatal(err)
	}
	rec := &sinktest.Recorded{}
	c := New(Options{UploadsDir: uploads, WebConfig: filepath.Join(dir, "not-apache.conf")})
	err := c.Collect(context.Background(), &protocol.Job{ID: "j"}, rec)
	if !errors.Is(err, collector.ErrNotApplicable) {
		t.Fatalf("want ErrNotApplicable, got %v", err)
	}
	if len(rec.Files) != 0 {
		t.Fatalf("files after skip: %+v", rec.Files)
	}
}

func TestNeedsConfigWithoutUploads(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "apache.conf")
	writeFile(t, config, "ok")
	// IIS default: no upload directory configured.
	rec := &sinktest.Recorded{}
	c := New(Options{UploadsDir: "", WebConfig: config})
	if err := c.Collect(context.Background(), &protocol.Job{ID: "j"}, rec); !errors.Is(err, collector.ErrNeedsConfig) {
		t.Fatalf("empty uploads: want ErrNeedsConfig, got %v", err)
	}
	// Configured but missing on disk.
	c = New(Options{UploadsDir: filepath.Join(dir, "missing"), WebConfig: config})
	if err := c.Collect(context.Background(), &protocol.Job{ID: "j"}, rec); !errors.Is(err, collector.ErrNeedsConfig) {
		t.Fatalf("missing uploads: want ErrNeedsConfig, got %v", err)
	}
}

func TestWebLogsNewestFirstWithNote(t *testing.T) {
	dir := t.TempDir()
	uploads := filepath.Join(dir, "uploads")
	if err := os.Mkdir(uploads, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "apache.conf")
	writeFile(t, config, "ok")
	base := time.Now().Add(-time.Hour)
	names := []string{}
	for i := 0; i < 6; i++ {
		name := filepath.Join(dir, "access"+string(rune('0'+i))+".log")
		writeFile(t, name, "line")
		at := base.Add(-time.Duration(i) * time.Hour)
		if err := os.Chtimes(name, at, at); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	rec := &sinktest.Recorded{}
	c := New(Options{UploadsDir: uploads, WebConfig: config, WebLogs: filepath.Join(dir, "*.log") + "," + names[0]})
	if err := c.Collect(context.Background(), &protocol.Job{ID: "logs"}, rec); err != nil {
		t.Fatal(err)
	}
	// 6 files found, only the newest 4 kept; the duplicate literal does not
	// consume a slot.
	if len(rec.Files) != maxLogFiles {
		t.Fatalf("log files: %d, want %d: %+v", len(rec.Files), maxLogFiles, rec.Files)
	}
	for i, want := range names[:maxLogFiles] {
		if rec.Files[i].Path != want || rec.Files[i].Kind != logKind() ||
			rec.Files[i].Reason != "web server log snapshot (live collection)" {
			t.Fatalf("log order/kind: %+v", rec.Files)
		}
	}
	if len(rec.Notes) != 1 || rec.Notes[0] != "log file limit reached; kept 4 newest of 6" {
		t.Fatalf("notes: %v", rec.Notes)
	}
	if len(rec.Problems) != 0 {
		t.Fatalf("dropped logs must not be failures: %v", rec.Problems)
	}
}
