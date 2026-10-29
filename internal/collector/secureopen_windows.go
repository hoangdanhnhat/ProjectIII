//go:build windows

package collector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SecureOpen opens path without traversing symlinks, junctions, or other
// reparse points. Every path component is checked with Lstat before the file
// is opened, and the open itself is performed through os.Root so a component
// swapped for a link cannot escape the volume. Windows has no O_NOFOLLOW, so
// the check/open pair is not atomic like the Linux implementation; the Root
// containment check bounds the damage of that race to the same volume.
func SecureOpen(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("expected a clean absolute path")
	}
	volume := filepath.VolumeName(path)
	if volume == "" {
		return nil, errors.New("expected a volume-qualified path")
	}
	rootName := volume + string(filepath.Separator)
	if path == volume || path == rootName {
		root, err := os.OpenRoot(rootName)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		return root.Open(".")
	}
	rel := strings.TrimPrefix(path, rootName)
	if strings.HasPrefix(rel, string(filepath.Separator)) {
		return nil, errors.New("expected a clean absolute path")
	}
	root, err := os.OpenRoot(rootName)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	parts := strings.Split(rel, string(filepath.Separator))
	for i := range parts {
		prefix := strings.Join(parts[:i+1], string(filepath.Separator))
		info, err := root.Lstat(prefix)
		if err != nil {
			return nil, err
		}
		// ModeSymlink covers symlinks and junctions; ModeIrregular covers
		// other reparse point tags that Go does not treat as regular files.
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil, fmt.Errorf("%s: symlink, junction, or reparse point is not allowed", prefix)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, fmt.Errorf("%s: path component is not a directory", prefix)
		}
	}
	return root.Open(rel)
}
