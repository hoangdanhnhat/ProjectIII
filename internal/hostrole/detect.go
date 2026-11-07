package hostrole

import (
	"context"
	"time"
)

// method describes how the profile was derived. Kept stable so artifacts can
// be compared across agent versions.
const method = "registry+service+filesystem-metadata"

// Source gathers the facts the classifier evaluates. The Windows
// implementation reads the registry and fixed paths; tests inject a fake.
type Source interface {
	Facts(ctx context.Context) (*Facts, error)
}

// Detect gathers facts from src and builds a profile stamped with the current
// UTC time.
func Detect(ctx context.Context, src Source) (*Profile, error) {
	facts, err := src.Facts(ctx)
	if err != nil {
		return nil, err
	}
	return Build(facts, time.Now().UTC()), nil
}

// Build classifies facts into a profile. now is passed in so tests are
// deterministic.
func Build(f *Facts, now time.Time) *Profile {
	if f == nil {
		f = &Facts{}
	}
	roles := Classify(f)
	profile := &Profile{
		SchemaVersion: 1,
		GeneratedAt:   now.UTC(),
		Method:        method,
		Host: Host{
			Hostname:    f.Hostname,
			ProductType: f.ProductType,
			HostClass:   HostClass(f.ProductType),
			OSName:      f.OSName,
			OSBuild:     f.OSBuild,
		},
		Roles:       roles,
		ProbeErrors: normalizeProbeErrors(f.ProbeErrors),
	}
	// A "possible" role is too weak to name the host after; host_class still
	// describes it.
	if len(roles) > 0 && roles[0].Tier != TierPossible {
		profile.PrimaryRole = roles[0].Role
	}
	return profile
}

func normalizeProbeErrors(errors []ProbeError) []ProbeError {
	if len(errors) == 0 {
		return nil
	}
	out := make([]ProbeError, 0, len(errors))
	seen := make(map[string]bool, len(errors))
	for _, item := range errors {
		if item.Source == "" && item.Detail == "" {
			continue
		}
		key := item.Source + "\x00" + item.Detail
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	sortProbeErrors(out)
	return out
}
