package hostrole

import (
	"context"
	"errors"
	"testing"

	"example.com/dfir-collector/internal/collector/sinktest"
	engine "example.com/dfir-collector/internal/hostrole"
	"example.com/dfir-collector/internal/protocol"
)

type fakeSource struct {
	facts *engine.Facts
	err   error
}

func (f fakeSource) Facts(context.Context) (*engine.Facts, error) {
	return f.facts, f.err
}

func TestCollectEmitsHostRoleArtifact(t *testing.T) {
	source := fakeSource{facts: &engine.Facts{
		Hostname:    "WEB01",
		ProductType: "ServerNT",
		Services:    map[string]engine.Service{"W3SVC": {Present: true, Start: 2, HasStart: true}},
		IIS:         &engine.IISFacts{Registry: true, MajorVersion: 10, ConfigPresent: true},
	}}
	rec := &sinktest.Recorded{}
	c := New(Options{Source: source})
	if err := c.Collect(context.Background(), &protocol.Job{ID: "role"}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.BytesCalls) != 1 {
		t.Fatalf("artifacts = %+v", rec.BytesCalls)
	}
	call := rec.BytesCalls[0]
	if call.Kind != protocol.KindHostRole || call.Name != "host_role.json" {
		t.Fatalf("artifact = %+v", call)
	}
	profile, err := engine.Parse(call.Data)
	if err != nil {
		t.Fatal(err)
	}
	if profile.PrimaryRole != engine.RoleWebServer {
		t.Fatalf("primary role = %q", profile.PrimaryRole)
	}
	if len(rec.Problems) != 0 {
		t.Fatalf("problems = %v", rec.Problems)
	}
}

func TestCollectReportsProbeFailureAsProblem(t *testing.T) {
	rec := &sinktest.Recorded{}
	c := New(Options{Source: fakeSource{err: errors.New("registry unavailable")}})
	if err := c.Collect(context.Background(), &protocol.Job{ID: "role"}, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.BytesCalls) != 0 {
		t.Fatalf("artifacts = %+v", rec.BytesCalls)
	}
	if len(rec.Problems) != 1 {
		t.Fatalf("problems = %v", rec.Problems)
	}
}
