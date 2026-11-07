package hostrole

import (
	"sort"
	"strings"
)

// Service is the installation state of one Windows service key.
type Service struct {
	Present  bool
	Start    uint32 // SERVICE_* start type from the registry
	HasStart bool
}

// Enabled reports whether the service is installed and not disabled.
func (s Service) Enabled() bool {
	return s.Present && (!s.HasStart || s.Start != serviceStartDisabled)
}

// Service start types from winnt.h.
const (
	serviceStartBoot     = 0
	serviceStartSystem   = 1
	serviceStartAuto     = 2
	serviceStartDemand   = 3
	serviceStartDisabled = 4
)

func startLabel(start uint32) string {
	switch start {
	case serviceStartBoot:
		return "boot"
	case serviceStartSystem:
		return "system"
	case serviceStartAuto:
		return "auto"
	case serviceStartDemand:
		return "manual"
	case serviceStartDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// Share is one configured SMB share. Path is the configured directory when
// the registry value provides it; it is never traversed.
type Share struct {
	Name string
	Path string
}

// IISFacts records the two independent IIS installation markers.
type IISFacts struct {
	Registry      bool // HKLM\SOFTWARE\Microsoft\InetStp exists
	MajorVersion  int
	ConfigPresent bool // applicationHost.config metadata is readable
}

// Facts is the platform-neutral snapshot gathered by a Source. The classifier
// depends only on this struct, so every scoring rule is testable on Linux.
type Facts struct {
	Hostname    string
	ProductType string
	OSName      string
	OSBuild     string

	Services      map[string]Service
	Shares        []Share
	IIS           *IISFacts
	NTDS          bool
	SQLInstances  []string
	Exchange      string // version key name, for example "v15"
	DNSDirectory  bool
	DHCPDirectory bool

	ProbeErrors []ProbeError
}

// Service returns a service by name, case-insensitively (Windows service names
// are case-insensitive).
func (f *Facts) Service(name string) (Service, bool) {
	for key, svc := range f.Services {
		if strings.EqualFold(key, name) {
			return svc, true
		}
	}
	return Service{}, false
}

// ServicesWithPrefix returns the installed service names that start with
// prefix, sorted for deterministic output.
func (f *Facts) ServicesWithPrefix(prefix string) []string {
	var names []string
	upper := strings.ToUpper(prefix)
	for name, svc := range f.Services {
		if svc.Present && strings.HasPrefix(strings.ToUpper(name), upper) {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToUpper(names[i]) < strings.ToUpper(names[j])
	})
	return names
}

// AddProbeError appends one bounded probe failure.
func (f *Facts) AddProbeError(source string, err error) {
	if err == nil {
		return
	}
	f.ProbeErrors = append(f.ProbeErrors, ProbeError{Source: source, Detail: err.Error()})
}
