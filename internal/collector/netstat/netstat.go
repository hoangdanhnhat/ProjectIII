// Package netstat implements the netstat.v1 scenario: a point-in-time
// snapshot of TCP and UDP endpoints with owning processes plus the DNS
// client resolver cache, rendered as a versioned JSON artifact. Cached
// names are correlated to connection remote addresses through A/AAAA and
// CNAME records so the server-side threat-intel enrichment knows which
// domain each connection reached.
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
	records, dnsErr := dnsCacheRecords(ctx)
	if dnsErr != nil {
		// The connection table is already collected; a missing DNS cache
		// downgrades the job to partial instead of failing it.
		sink.Problem("DNS client cache: %v", dnsErr)
	} else {
		snap.DNSCache = records
		Correlate(snap)
	}
	data := Render(snap)
	return sink.Bytes(protocol.KindNetstatSnapshot, "netstat_snapshot.json",
		"TCP/UDP endpoint snapshot with owning processes, DNS client cache and domain correlation", data)
}
