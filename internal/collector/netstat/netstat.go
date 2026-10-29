// Package netstat implements the netstat.v1 scenario: a point-in-time
// snapshot of TCP and UDP endpoints with owning processes, rendered as a
// versioned JSON artifact.
//
// job.Since does not apply: the snapshot describes the moment of collection.
package netstat

import (
	"context"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// New returns the netstat.v1 collector.
func New() collector.Collector { return &scenario{} }

type scenario struct{}

func (s *scenario) ID() string          { return protocol.ScenarioNetstat }
func (s *scenario) Platforms() []string { return []string{"windows"} }

func (s *scenario) Collect(ctx context.Context, job *protocol.Job, sink collector.Sink) error {
	snap, err := snapshot()
	if err != nil {
		sink.Problem("endpoint table snapshot failed: %v", err)
		return nil
	}
	data := Render(snap)
	return sink.Bytes(protocol.KindNetstatSnapshot, "netstat_snapshot.json",
		"TCP/UDP endpoint table snapshot with owning processes", data)
}
