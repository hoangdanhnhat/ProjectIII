// Package hostrole implements the hostrole.v1 scenario: a versioned profile
// of the server roles a Windows host appears to hold, derived from passive
// registry, service and filesystem-metadata probes.
package hostrole

import (
	"context"

	"example.com/dfir-collector/internal/collector"
	engine "example.com/dfir-collector/internal/hostrole"
	"example.com/dfir-collector/internal/protocol"
)

// Options configures the scenario. Source is injectable for tests; production
// uses the Windows registry/filesystem probe from the hostrole engine.
type Options struct {
	Source engine.Source
}

// New returns the hostrole.v1 collector.
func New(o Options) collector.Collector {
	return &scenario{opts: o}
}

type scenario struct {
	opts Options
}

func (s *scenario) ID() string          { return protocol.ScenarioHostRole }
func (s *scenario) Platforms() []string { return []string{"windows"} }

func (s *scenario) Collect(ctx context.Context, job *protocol.Job, sink collector.Sink) error {
	source := s.opts.Source
	if source == nil {
		source = engine.NewSource()
	}
	profile, err := engine.Detect(ctx, source)
	if err != nil {
		// The role profile is the only artifact of this scenario; a probe
		// failure is reported as a job problem instead of a transport error.
		sink.Problem("host role detection failed: %v", err)
		return nil
	}
	return sink.Bytes(protocol.KindHostRole, "host_role.json",
		"Windows host role profile derived from registry, service and filesystem metadata",
		engine.Render(profile))
}
