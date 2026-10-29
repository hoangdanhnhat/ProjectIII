//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureOpenWindows(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.php")
	if err := os.WriteFile(file, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := SecureOpen(file)
	if err != nil {
		t.Fatalf("regular file: %v", err)
	}
	f.Close()

	sep := string(filepath.Separator)
	if f, err := SecureOpen(dir + sep + ".." + sep + filepath.Base(dir) + sep + "test.php"); err == nil {
		f.Close()
		t.Fatal("accepted unclean path")
	}
	if f, err := SecureOpen("test.php"); err == nil {
		f.Close()
		t.Fatal("accepted relative path")
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("cannot create symlink in this environment: %v", err)
	}
	if f, err := SecureOpen(filepath.Join(link, "test.php")); err == nil {
		f.Close()
		t.Fatal("followed symlinked parent")
	}
}
