//go:build linux

package collector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// SecureOpen resolves every component from / using directory descriptors and
// O_NOFOLLOW, so neither symlinked files nor symlinked parent directories
// are read.
func SecureOpen(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("expected a clean absolute path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if path == "/" {
		return os.NewFile(uintptr(fd), path), nil
	}
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, err := syscall.Openat(fd, part, flags, 0)
		_ = syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}
