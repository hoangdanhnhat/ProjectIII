// Package hostrole classifies a Windows host's server role from passive,
// read-only facts: registry keys, service installation keys and a handful of
// fixed filesystem paths. It never runs commands, queries the network, or
// reads file contents.
//
// The output is an evidence-backed profile, not a proof of what the host is
// currently serving. A host can legitimately hold several roles (a domain
// controller usually is also a DNS and file server), so Classify returns a
// sorted list rather than a single label.
package hostrole

import "time"

// Role is one server role this package can recognise. Third-party web and
// database servers are intentionally out of scope for schema version 1.
type Role string

const (
	RoleDomainController Role = "domain_controller"
	RoleWebServer        Role = "web_server"
	RoleFileServer       Role = "file_server"
	RoleDatabaseServer   Role = "database_server"
	RoleMailServer       Role = "mail_server"
	RoleDNSServer        Role = "dns_server"
	RoleDHCPServer       Role = "dhcp_server"
)

// roleOrder is the documented tie-break order: infrastructure roles first.
var roleOrder = []Role{
	RoleDomainController,
	RoleWebServer,
	RoleFileServer,
	RoleDatabaseServer,
	RoleMailServer,
	RoleDNSServer,
	RoleDHCPServer,
}

func roleRank(r Role) int {
	for i, candidate := range roleOrder {
		if candidate == r {
			return i
		}
	}
	return len(roleOrder)
}

// Strength describes how much one piece of evidence supports a role.
type Strength string

const (
	// StrengthDefinitive marks software that is installed, or an OS setting
	// that declares the role.
	StrengthDefinitive Strength = "definitive"
	// StrengthStrong is independent confirmation, such as a role service.
	StrengthStrong Strength = "strong"
	// StrengthSupporting corroborates but is not sufficient alone.
	StrengthSupporting Strength = "supporting"
)

// Weights turn evidence into a 0-100 score. Confirmed needs two strong
// signals or one definitive signal; probable needs one strong signal.
const (
	weightDefinitive = 100
	weightStrong     = 50
	weightSupporting = 15

	scoreConfirmed = 80
	scoreProbable  = 50
	scorePossible  = 20
)

func evidenceWeight(s Strength) int {
	switch s {
	case StrengthDefinitive:
		return weightDefinitive
	case StrengthStrong:
		return weightStrong
	case StrengthSupporting:
		return weightSupporting
	default:
		return 0
	}
}

// Tier is the human-facing confidence band of a role result.
type Tier string

const (
	TierConfirmed Tier = "confirmed"
	TierProbable  Tier = "probable"
	TierPossible  Tier = "possible"
)

func tierFor(score int) Tier {
	switch {
	case score >= scoreConfirmed:
		return TierConfirmed
	case score >= scoreProbable:
		return TierProbable
	default:
		return TierPossible
	}
}

// Evidence is one observed fact supporting a role. Source names the probe
// location (registry path, service name, or fixed file path) so an analyst can
// reproduce the observation.
type Evidence struct {
	Strength Strength `json:"strength"`
	Source   string   `json:"source"`
	Detail   string   `json:"detail"`
}

// RoleResult is one role with its evidence and derived confidence.
type RoleResult struct {
	Role       Role       `json:"role"`
	Confidence float64    `json:"confidence"`
	Tier       Tier       `json:"tier"`
	Evidence   []Evidence `json:"evidence"`
}

// Host describes the OS-level identity used to separate a workstation from a
// server and from a domain controller.
type Host struct {
	Hostname    string `json:"hostname"`
	ProductType string `json:"product_type,omitempty"`
	HostClass   string `json:"host_class"`
	OSName      string `json:"os_name,omitempty"`
	OSBuild     string `json:"os_build,omitempty"`
}

// Host classes derived from ProductOptions\ProductType.
const (
	HostClassDomainController = "domain_controller"
	HostClassServer           = "server"
	HostClassWorkstation      = "workstation"
	HostClassUnknown          = "unknown"
)

// HostClass maps the ProductType registry value to a coarse host class.
func HostClass(productType string) string {
	switch productType {
	case "LanmanNT":
		return HostClassDomainController
	case "ServerNT":
		return HostClassServer
	case "WinNT":
		return HostClassWorkstation
	default:
		return HostClassUnknown
	}
}

// ProbeError records an unreadable key or path. It is informational: the
// profile is still emitted with whatever evidence was available.
type ProbeError struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
}

// Profile is the rendered host_role.json artifact.
type Profile struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Method        string       `json:"method"`
	Host          Host         `json:"host"`
	PrimaryRole   Role         `json:"primary_role,omitempty"`
	Roles         []RoleResult `json:"roles"`
	ProbeErrors   []ProbeError `json:"probe_errors,omitempty"`
}
