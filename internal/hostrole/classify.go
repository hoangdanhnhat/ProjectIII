package hostrole

import (
	"fmt"
	"sort"
	"strings"
)

// Classify turns facts into ranked role results. Only roles scoring at least
// scorePossible are returned; the caller decides whether the best result is
// strong enough to be called a primary role.
func Classify(f *Facts) []RoleResult {
	if f == nil {
		return []RoleResult{}
	}
	results := make([]RoleResult, 0, len(roleOrder))
	add := func(role Role, evidence []Evidence) {
		evidence = normalizeEvidence(evidence)
		if len(evidence) == 0 {
			return
		}
		score := 0
		for _, item := range evidence {
			score += evidenceWeight(item.Strength)
		}
		if score > 100 {
			score = 100
		}
		if score < scorePossible {
			return
		}
		results = append(results, RoleResult{
			Role:       role,
			Confidence: float64(score) / 100,
			Tier:       tierFor(score),
			Evidence:   evidence,
		})
	}

	add(RoleDomainController, domainControllerEvidence(f))
	add(RoleWebServer, webServerEvidence(f))
	add(RoleFileServer, fileServerEvidence(f))
	add(RoleDatabaseServer, databaseEvidence(f))
	add(RoleMailServer, mailEvidence(f))
	add(RoleDNSServer, dnsEvidence(f))
	add(RoleDHCPServer, dhcpEvidence(f))

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Confidence != results[j].Confidence {
			return results[i].Confidence > results[j].Confidence
		}
		return roleRank(results[i].Role) < roleRank(results[j].Role)
	})
	return results
}

func domainControllerEvidence(f *Facts) []Evidence {
	var evidence []Evidence
	if f.ProductType == "LanmanNT" {
		evidence = append(evidence, Evidence{
			Strength: StrengthDefinitive,
			Source:   `registry:HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions`,
			Detail:   "ProductType=LanmanNT declares a domain controller",
		})
	}
	if f.NTDS {
		evidence = append(evidence, Evidence{
			Strength: StrengthDefinitive,
			Source:   `file:%SystemRoot%\NTDS\ntds.dit`,
			Detail:   "Active Directory database present",
		})
	}
	if svc, ok := f.Service("NTDS"); ok {
		evidence = append(evidence, serviceEvidence("NTDS", svc, StrengthStrong))
	}
	if svc, ok := f.Service("Netlogon"); ok {
		evidence = append(evidence, serviceEvidence("Netlogon", svc, StrengthSupporting))
	}
	if hasShare(f.Shares, "SYSVOL") {
		evidence = append(evidence, Evidence{
			Strength: StrengthSupporting,
			Source:   `registry:HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`,
			Detail:   "SYSVOL share present",
		})
	}
	if hasShare(f.Shares, "NETLOGON") {
		evidence = append(evidence, Evidence{
			Strength: StrengthSupporting,
			Source:   `registry:HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`,
			Detail:   "NETLOGON share present",
		})
	}
	return evidence
}

func webServerEvidence(f *Facts) []Evidence {
	var evidence []Evidence
	if f.IIS != nil && f.IIS.Registry {
		detail := "IIS installation key present"
		if f.IIS.MajorVersion > 0 {
			detail = fmt.Sprintf("IIS installation key present (MajorVersion=%d)", f.IIS.MajorVersion)
		}
		evidence = append(evidence, Evidence{
			Strength: StrengthDefinitive,
			Source:   `registry:HKLM\SOFTWARE\Microsoft\InetStp`,
			Detail:   detail,
		})
	}
	if f.IIS != nil && f.IIS.ConfigPresent {
		evidence = append(evidence, Evidence{
			Strength: StrengthDefinitive,
			Source:   `file:%SystemRoot%\System32\inetsrv\config\applicationHost.config`,
			Detail:   "IIS configuration file present",
		})
	}
	if svc, ok := f.Service("W3SVC"); ok {
		evidence = append(evidence, serviceEvidence("W3SVC", svc, StrengthStrong))
	}
	return evidence
}

func fileServerEvidence(f *Facts) []Evidence {
	var evidence []Evidence
	custom := CustomShares(f.Shares)
	if len(custom) > 0 {
		names := make([]string, 0, len(custom))
		for _, share := range custom {
			names = append(names, share.Name)
		}
		evidence = append(evidence, Evidence{
			Strength: StrengthDefinitive,
			Source:   `registry:HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`,
			Detail:   "non-default SMB share(s): " + strings.Join(names, ", "),
		})
	}
	if svc, ok := f.Service("LanmanServer"); ok && svc.Enabled() {
		evidence = append(evidence, serviceEvidence("LanmanServer", svc, StrengthSupporting))
	}
	return evidence
}

func databaseEvidence(f *Facts) []Evidence {
	var evidence []Evidence
	if len(f.SQLInstances) > 0 {
		instances := dedupeSorted(f.SQLInstances)
		evidence = append(evidence, Evidence{
			Strength: StrengthDefinitive,
			Source:   `registry:HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`,
			Detail:   "SQL Server instance(s): " + strings.Join(instances, ", "),
		})
	}
	var services []string
	for _, name := range f.ServicesWithPrefix("MSSQL") {
		services = append(services, name)
	}
	if len(services) > 0 {
		evidence = append(evidence, Evidence{
			Strength: StrengthStrong,
			Source:   "service:" + strings.Join(services, ","),
			Detail:   "SQL Server service(s) installed",
		})
	}
	return evidence
}

func mailEvidence(f *Facts) []Evidence {
	var evidence []Evidence
	if f.Exchange != "" {
		evidence = append(evidence, Evidence{
			Strength: StrengthDefinitive,
			Source:   `registry:HKLM\SOFTWARE\Microsoft\ExchangeServer\` + f.Exchange + `\Setup`,
			Detail:   "Exchange Server setup key present (" + f.Exchange + ")",
		})
	}
	if svc, ok := f.Service("MSExchangeIS"); ok {
		evidence = append(evidence, serviceEvidence("MSExchangeIS", svc, StrengthStrong))
	}
	if svc, ok := f.Service("MSExchangeTransport"); ok {
		evidence = append(evidence, serviceEvidence("MSExchangeTransport", svc, StrengthSupporting))
	}
	return evidence
}

func dnsEvidence(f *Facts) []Evidence {
	var evidence []Evidence
	if svc, ok := f.Service("DNS"); ok {
		evidence = append(evidence, serviceEvidence("DNS", svc, StrengthStrong))
	}
	if f.DNSDirectory {
		evidence = append(evidence, Evidence{
			Strength: StrengthSupporting,
			Source:   `file:%SystemRoot%\System32\dns`,
			Detail:   "DNS server data directory present",
		})
	}
	return evidence
}

func dhcpEvidence(f *Facts) []Evidence {
	var evidence []Evidence
	if svc, ok := f.Service("DHCPServer"); ok {
		evidence = append(evidence, serviceEvidence("DHCPServer", svc, StrengthStrong))
	}
	if f.DHCPDirectory {
		evidence = append(evidence, Evidence{
			Strength: StrengthSupporting,
			Source:   `file:%SystemRoot%\System32\dhcp`,
			Detail:   "DHCP server data directory present",
		})
	}
	return evidence
}

func serviceEvidence(name string, svc Service, strength Strength) Evidence {
	detail := "service present"
	if svc.HasStart {
		detail = "service present, Start=" + startLabel(svc.Start)
	}
	return Evidence{Strength: strength, Source: "service:" + name, Detail: detail}
}

func normalizeEvidence(evidence []Evidence) []Evidence {
	out := make([]Evidence, 0, len(evidence))
	seen := make(map[string]bool, len(evidence))
	for _, item := range evidence {
		if item.Strength == "" || item.Source == "" {
			continue
		}
		key := string(item.Strength) + "\x00" + item.Source + "\x00" + item.Detail
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].Strength != out[j].Strength {
			return out[i].Strength < out[j].Strength
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

func dedupeSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToUpper(strings.TrimSpace(value))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, strings.TrimSpace(value))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToUpper(out[i]) < strings.ToUpper(out[j])
	})
	return out
}
