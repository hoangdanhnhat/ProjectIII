// Package webshell implements the webshell.v1 scenario: script-like files
// from a configured upload directory, plus snapshots of the newest web
// server logs. It is a collection aid, not a detection claim.
package webshell

import (
	"context"
	"fmt"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// Options configures the scenario. All paths are explicit: the collector
// never guesses an upload directory (IIS has no standard one) and never
// scans outside the configured directory.
type Options struct {
	UploadsDir string // upload directory to walk
	WebConfig  string // web server config used for role detection
	WebLogs    string // comma-separated log paths or glob patterns
}

// New returns the webshell.v1 collector.
func New(o Options) collector.Collector {
	return &scenario{opts: o}
}

type scenario struct {
	opts Options
}

func (s *scenario) ID() string          { return protocol.ScenarioWebshell }
func (s *scenario) Platforms() []string { return []string{"linux", "windows"} }

func (s *scenario) Collect(ctx context.Context, job *protocol.Job, sink collector.Sink) error {
	// Role detection: a readable web server configuration identifies this
	// host as a web server. Without it the scenario does not apply.
	if f, err := collector.SecureOpen(s.opts.WebConfig); err != nil {
		return fmt.Errorf("%w: web server configuration not found or unreadable", collector.ErrNotApplicable)
	} else {
		f.Close()
	}
	if s.opts.UploadsDir == "" {
		return fmt.Errorf("%w: upload directory not configured", collector.ErrNeedsConfig)
	}
	if err := s.collectUploads(job, sink); err != nil {
		return err
	}
	return s.collectLogs(sink)
}
