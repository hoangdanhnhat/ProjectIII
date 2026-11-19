package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// profile is one supported acquisition tool: its fixed argv template and the
// extension of the image it writes. Arguments are built by code only; no
// shell is involved and no host value other than the collector-generated
// output path reaches argv.
type profile struct {
	name string
	ext  string
	args func(output string) []string
	// okExit reports whether a non-zero exit code still means the tool
	// completed the acquisition. WinPmem's main() returns the result of
	// write_raw_image() directly: 1 on success and -1 (0xFFFFFFFF) on
	// failure, so 0 is never a success code for this tool.
	okExit func(code int) bool
}

func winpmemExit(code int) bool { return code == 1 }

var profiles = map[string]profile{
	// WinPmem 4.0.1 CLI: WinPmem64.exe <image.raw>. The output path is
	// positional; there is no -o option. The two names only differ in the
	// identity recorded in the manifest, so an operator can say which build
	// was deployed.
	"winpmem": {
		name:   "winpmem",
		ext:    ".raw",
		args:   func(output string) []string { return []string{output} },
		okExit: winpmemExit,
	},
	// winpmem_mini_x64_rc2.exe takes the output path the same way.
	"winpmem-mini": {
		name:   "winpmem-mini",
		ext:    ".raw",
		args:   func(output string) []string { return []string{output} },
		okExit: winpmemExit,
	},
	// WinPmem 4.0.1's -1 flag selects the \\.\PhysicalMemory method instead
	// of PTE remapping. The PTE default produced corrupt images on the
	// Server 2016 lab VM (repeated pages, no kernel), while -1 produced an
	// image Volatility 3 could parse.
	"winpmem-physical": {
		name:   "winpmem-physical",
		ext:    ".raw",
		args:   func(output string) []string { return []string{"-1", output} },
		okExit: winpmemExit,
	},
}

// lookupProfile resolves -memory-tool-name, or derives the profile from the
// executable name when the flag is empty.
func lookupProfile(name, toolPath string) (profile, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		base := strings.ToLower(filepath.Base(toolPath))
		switch {
		case strings.Contains(base, "winpmem") && strings.Contains(base, "mini"):
			name = "winpmem-mini"
		case strings.Contains(base, "winpmem"):
			name = "winpmem"
		default:
			return profile{}, fmt.Errorf("unknown capture tool %q: set -memory-tool-name (winpmem, winpmem-mini)", filepath.Base(toolPath))
		}
	}
	p, ok := profiles[name]
	if !ok {
		return profile{}, fmt.Errorf("unsupported -memory-tool-name %q (supported: winpmem, winpmem-mini)", name)
	}
	return p, nil
}

// captureName builds the staged image name. The job ID is embedded so a
// retried job can find the capture from the previous attempt.
func captureName(hostID, jobID, ext string, at time.Time) string {
	return capturePrefix(hostID, jobID) + at.UTC().Format("20060102T150405Z") + ext
}

func capturePrefix(hostID, jobID string) string {
	return "memory-" + sanitizeComponent(hostID) + "-" + sanitizeComponent(jobID) + "-"
}

// sanitizeComponent keeps file names readable while removing path separators,
// glob metacharacters and control characters.
func sanitizeComponent(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 80 {
			break
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// findCapture returns the newest non-empty image left by an earlier attempt
// of the same job. Only regular files are considered; symlinks are ignored.
// Names embed a fixed-width UTC timestamp, so the lexicographically greatest
// match is also the newest capture.
func findCapture(dir, hostID, jobID, ext string) (string, bool) {
	pattern := filepath.Join(dir, capturePrefix(hostID, jobID)+"*"+ext)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", false
	}
	best := ""
	for _, match := range matches {
		info, err := os.Lstat(match)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		if match > best {
			best = match
		}
	}
	return best, best != ""
}
