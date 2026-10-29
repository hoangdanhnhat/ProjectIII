//go:build !windows

package eventlog

import (
	"context"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// collectChannels is only implemented on Windows (a Linux journald/syslog
// variant is planned). The registry filters unsupported platforms before
// Collect runs, so this stub only keeps non-Windows builds compiling.
func (s *scenario) collectChannels(ctx context.Context, job *protocol.Job, sink collector.Sink) error {
	return collector.ErrNotApplicable
}
