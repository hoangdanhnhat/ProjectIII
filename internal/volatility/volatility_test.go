//go:build !windows

package volatility

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "memory.raw")
	if err := os.WriteFile(path, []byte("fake memory image"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeWrapper(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "vol-wrapper")
	script := `#!/bin/sh
img=""
out=""
mods=""
while [ $# -gt 0 ]; do
  case "$1" in
    -i) img="$2"; shift 2 ;;
    -o) out="$2"; shift 2 ;;
    -m) mods="$2"; shift 2 ;;
    *) shift ;;
  esac
done
base=$(basename "$img")
` + body
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseConfig(t *testing.T, wrapper string) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		VolPath:     "/bin/true",
		WrapperPath: wrapper,
		SymbolsDir:  filepath.Join(root, "symbols"),
		CacheDir:    filepath.Join(root, "cache"),
		WorkRoot:    filepath.Join(root, "work"),
		Plugins:     []string{"windows.info.Info", "windows.pslist.PsList"},
		Timeout:     10 * time.Second,
		MaxOutput:   1 << 20,
		Now:         func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) },
	}
}

func TestLoadPlugins(t *testing.T) {
	plugins, err := LoadPlugins("")
	if err != nil || len(plugins) != len(DefaultPlugins) {
		t.Fatalf("default: %v %d", err, len(plugins))
	}
	path := filepath.Join(t.TempDir(), "plugins.txt")
	if err := os.WriteFile(path, []byte("# comment\n\nwindows.info.Info\n  windows.pslist.PsList  \n"), 0600); err != nil {
		t.Fatal(err)
	}
	plugins, err = LoadPlugins(path)
	if err != nil || len(plugins) != 2 || plugins[0] != "windows.info.Info" || plugins[1] != "windows.pslist.PsList" {
		t.Fatalf("file: %v %v", err, plugins)
	}
	if _, err := LoadPlugins(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("missing plugin list accepted")
	}
}

func TestRunSuccess(t *testing.T) {
	wrapper := fakeWrapper(t, `while IFS= read -r p; do
  [ -z "$p" ] && continue
  printf '{"plugin":"%s"}\n' "$p" > "$out/${base}_${p}.jsonl"
  printf '    Module %s completed in 1.25 seconds\n' "$p"
done < "$mods"
exit 0
`)
	cfg := baseConfig(t, wrapper)
	image := fakeImage(t)
	r := New(cfg)
	report, outputs, err := r.Run(context.Background(), Input{
		JobID:     "job/../1",
		HostID:    "lab",
		ImagePath: image,
		Image:     ImageRef{ArtifactID: "img1", SHA256: "abc", Size: 18},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Completed != 2 || report.Summary.Failed != 0 || report.Summary.Rows != 2 {
		t.Fatalf("summary: %+v", report.Summary)
	}
	if len(outputs) != 2 || outputs[0].Rows != 1 || outputs[0].Size == 0 {
		t.Fatalf("outputs: %+v", outputs)
	}
	if report.Plugins[0].DurationMS != 1250 || report.Plugins[0].Status != StatusCompleted {
		t.Fatalf("plugin: %+v", report.Plugins[0])
	}
	if report.Image.ArtifactID != "img1" || report.Engine.Version != DefaultEngineVersion {
		t.Fatalf("report: %+v", report)
	}
	if len(report.Notes) == 0 || !strings.Contains(strings.Join(report.Notes, " "), "derived evidence") {
		t.Fatalf("notes: %v", report.Notes)
	}
	// The work directory is cleaned up.
	entries, err := os.ReadDir(cfg.WorkRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("workdir not removed: %v", entries)
	}
}

func TestRunPartialFailure(t *testing.T) {
	wrapper := fakeWrapper(t, `while IFS= read -r p; do
  [ -z "$p" ] && continue
  if [ "$p" = "windows.pslist.PsList" ]; then
    printf '!--- Error running module %s: boom\n' "$p"
    continue
  fi
  printf '{"plugin":"%s"}\n' "$p" > "$out/${base}_${p}.jsonl"
  printf '    Module %s completed in 1.25 seconds\n' "$p"
done < "$mods"
exit 1
`)
	report, outputs, err := New(baseConfig(t, wrapper)).Run(context.Background(), Input{
		JobID: "j", ImagePath: fakeImage(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Completed != 1 || report.Summary.Failed != 1 || len(outputs) != 1 {
		t.Fatalf("report: %+v outputs=%d", report.Summary, len(outputs))
	}
	var failed PluginResult
	for _, result := range report.Plugins {
		if result.Status == StatusFailed {
			failed = result
		}
	}
	if failed.Name != "windows.pslist.PsList" || !strings.Contains(failed.Error, "boom") {
		t.Fatalf("failed plugin: %+v", failed)
	}
}

func TestRunOversizedOutput(t *testing.T) {
	wrapper := fakeWrapper(t, `while IFS= read -r p; do
  printf '01234567890123456789' > "$out/${base}_${p}.jsonl"
  printf '    Module %s completed in 1.00 seconds\n' "$p"
done < "$mods"
exit 0
`)
	cfg := baseConfig(t, wrapper)
	cfg.Plugins = []string{"windows.info.Info"}
	cfg.MaxOutput = 10
	report, outputs, err := New(cfg).Run(context.Background(), Input{JobID: "j", ImagePath: fakeImage(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 0 || report.Summary.Oversized != 1 || report.Summary.Failed != 1 {
		t.Fatalf("report: %+v outputs=%d", report.Summary, len(outputs))
	}
	if report.Plugins[0].Status != statusOversized || !strings.Contains(report.Plugins[0].Error, "above") {
		t.Fatalf("plugin: %+v", report.Plugins[0])
	}
}

func TestRunTimeout(t *testing.T) {
	wrapper := fakeWrapper(t, "sleep 5\nexit 0\n")
	cfg := baseConfig(t, wrapper)
	cfg.Plugins = []string{"windows.info.Info"}
	cfg.Timeout = 150 * time.Millisecond
	start := time.Now()
	report, _, err := New(cfg).Run(context.Background(), Input{JobID: "j", ImagePath: fakeImage(t)})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout did not kill the process group quickly: %s", time.Since(start))
	}
	if report == nil || report.Summary.Completed != 0 {
		t.Fatalf("report: %+v", report)
	}
}

func TestRunNoKernelLayer(t *testing.T) {
	wrapper := fakeWrapper(t, `printf 'Unable to validate the plugin requirements: [kernel]\n'
printf 'A translation layer requirement was not fulfilled.\n'
exit 1
`)
	report, outputs, err := New(baseConfig(t, wrapper)).Run(context.Background(), Input{JobID: "j", ImagePath: fakeImage(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 0 || report.Summary.Completed != 0 {
		t.Fatalf("report: %+v", report.Summary)
	}
	if !strings.Contains(strings.Join(report.Notes, " "), "no usable Windows kernel layer") {
		t.Fatalf("notes: %v", report.Notes)
	}
}

func TestRunMissingWrapper(t *testing.T) {
	cfg := baseConfig(t, filepath.Join(t.TempDir(), "missing"))
	report, outputs, err := New(cfg).Run(context.Background(), Input{JobID: "j", ImagePath: fakeImage(t)})
	if err == nil || !strings.Contains(err.Error(), "start volatility wrapper") {
		t.Fatalf("got %v", err)
	}
	if report != nil || outputs != nil {
		t.Fatalf("report=%v outputs=%v", report, outputs)
	}
}

func TestRenderNilSlices(t *testing.T) {
	data := Render(&Report{})
	if !strings.Contains(string(data), `"plugins": []`) || !strings.Contains(string(data), `"notes": []`) {
		t.Fatalf("render: %s", data)
	}
}
