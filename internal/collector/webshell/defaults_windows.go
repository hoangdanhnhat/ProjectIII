//go:build windows

package webshell

import (
	"os"
	"path/filepath"

	"example.com/dfir-collector/internal/protocol"
)

// windowsDir returns %SystemRoot% without a trailing separator, falling back
// to the standard location if the variable is missing.
func windowsDir() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return filepath.Clean(root)
	}
	return `C:\Windows`
}

// systemDrive returns %SystemDrive% without a trailing separator.
func systemDrive() string {
	if drive := os.Getenv("SystemDrive"); drive != "" {
		return filepath.Clean(drive)
	}
	return `C:`
}

// DefaultUploadsDir is deliberately empty: IIS has no standard upload
// directory, and the collector must not guess one. Set -uploads explicitly.
func DefaultUploadsDir() string { return "" }

func DefaultWebConfig() string {
	return filepath.Join(windowsDir(), "System32", "inetsrv", "config", "applicationHost.config")
}

// DefaultWebLogs prefers the IIS 7+ log root and falls back to the legacy
// IIS 6 location. Settings in applicationHost.config may point elsewhere; set
// -web-logs explicitly in that case.
func DefaultWebLogs() string {
	logRoots := []string{
		filepath.Join(systemDrive(), "inetpub", "logs", "LogFiles"),
		filepath.Join(windowsDir(), "System32", "LogFiles"),
	}
	for _, root := range logRoots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return filepath.Join(root, "W3SVC*", "*.log")
		}
	}
	return filepath.Join(logRoots[0], "W3SVC*", "*.log")
}

func logKind() protocol.Kind { return protocol.KindIISLog }
