//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureOpenRejectsSymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actual, "test.php"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	if f, err := SecureOpen(filepath.Join(link, "test.php")); err == nil {
		f.Close()
		t.Fatal("followed symlink parent")
	}
	if f, err := SecureOpen(filepath.Join(actual, "test.php")); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	if f, err := SecureOpen(actual + "/../actual/test.php"); err == nil {
		f.Close()
		t.Fatal("accepted unclean path")
	}
}
