package hostrole

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Render serializes a profile as deterministic, indented JSON. Roles and
// evidence are sorted first so two profiles of the same host state produce
// identical bytes apart from generated_at.
func Render(p *Profile) []byte {
	normalizeProfile(p)
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		// These types cannot fail to marshal; keep the failure loud anyway.
		return []byte(`{"error":"render failed"}`)
	}
	return data
}

// Parse decodes a rendered profile and rejects unknown schema versions.
func Parse(data []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("host role profile decode: %w", err)
	}
	if p.SchemaVersion != 1 {
		return nil, fmt.Errorf("host role schema_version %d not supported", p.SchemaVersion)
	}
	return &p, nil
}

func normalizeProfile(p *Profile) {
	if p == nil {
		return
	}
	if p.Roles == nil {
		p.Roles = []RoleResult{}
	}
	for i := range p.Roles {
		p.Roles[i].Evidence = normalizeEvidence(p.Roles[i].Evidence)
		if p.Roles[i].Evidence == nil {
			p.Roles[i].Evidence = []Evidence{}
		}
	}
	sort.SliceStable(p.Roles, func(i, j int) bool {
		if p.Roles[i].Confidence != p.Roles[j].Confidence {
			return p.Roles[i].Confidence > p.Roles[j].Confidence
		}
		return roleRank(p.Roles[i].Role) < roleRank(p.Roles[j].Role)
	})
	p.ProbeErrors = normalizeProbeErrors(p.ProbeErrors)
}

func sortProbeErrors(errors []ProbeError) {
	sort.SliceStable(errors, func(i, j int) bool {
		if errors[i].Source != errors[j].Source {
			return errors[i].Source < errors[j].Source
		}
		return errors[i].Detail < errors[j].Detail
	})
}
