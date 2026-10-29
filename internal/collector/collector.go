// Package collector defines the contract between the agent core and the
// scenario collectors it runs, plus small helpers shared by collectors.
//
// Invariants for every collector implementation:
//   - never run shell commands; subprocesses are allowed only for vetted
//     system binaries invoked with fixed arguments, documented per scenario
//   - never follow symlinks, junctions, or other reparse points
//   - read only explicitly configured paths, or paths derived from explicit
//     configuration; never scan broadly to guess a location
//   - honor job.Since where the artifact type supports it
//   - keep scenario-local limits inside the scenario; system-wide limits
//     (artifact size, artifacts per job) are enforced by the agent core and
//     the server
package collector

import (
	"context"
	"errors"

	"example.com/dfir-collector/internal/protocol"
)

// Sentinel outcomes. Collectors wrap them with fmt.Errorf("%w: ...") to add
// host-specific detail; the agent core maps them to job results.
var (
	// ErrNotApplicable marks a host that does not match the scenario (for
	// example a web server scenario on a host without a web server). The
	// agent reports the job as "skipped".
	ErrNotApplicable = errors.New("scenario not applicable to this host")

	// ErrNeedsConfig marks missing required configuration (for example no
	// -uploads flag on IIS). The agent reports "needs_configuration".
	ErrNeedsConfig = errors.New("required configuration missing")
)

// Sink receives evidence from a collector. The agent core implements it:
// every File and Bytes call is size-checked, hashed, uploaded once, and
// counted toward the final job result.
type Sink interface {
	// File collects a file from an absolute path. The core opens the path
	// without following symlinks, verifies the file did not change while
	// reading, and uploads it. File-level problems (unreadable, too large,
	// changed while reading) are recorded as failures on the sink and do
	// not abort collection; only transport errors are returned.
	File(kind protocol.Kind, path, reason string) error

	// Bytes collects synthesized evidence produced in memory, for example a
	// parsed Windows API or /proc snapshot rendered as JSON.
	Bytes(kind protocol.Kind, name, reason string, data []byte) error

	// Problem records a collection failure; it turns the job "partial" (or
	// "failed" if nothing was collected) and appears in the final reason.
	Problem(format string, args ...any)

	// Note records an informational detail that appears in the final reason
	// without affecting the job status.
	Note(format string, args ...any)
}

// Collector implements one scenario on one or more platforms.
type Collector interface {
	// ID is the scenario ID served, for example protocol.ScenarioWebshell.
	ID() string

	// Platforms lists the GOOS values where Collect is implemented.
	Platforms() []string

	// Collect finds evidence for the job and hands it to the sink. A nil
	// return means the collector finished; the sink's records decide the
	// final result.
	Collect(ctx context.Context, job *protocol.Job, sink Sink) error
}
