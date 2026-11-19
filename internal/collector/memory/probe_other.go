//go:build !windows

package memory

import "errors"

// probeHost is only implemented on Windows. The collector advertises Windows
// platforms, so the agent core filters memory.v1 jobs on other hosts; this
// stub keeps the package buildable and testable elsewhere (tests inject
// Options.Probe).
func probeHost(string) (Probe, error) {
	return Probe{}, errors.New("memory capture is only implemented on Windows")
}
