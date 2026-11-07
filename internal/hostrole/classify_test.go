package hostrole

import "testing"

func service(start uint32) Service {
	return Service{Present: true, Start: start, HasStart: true}
}

func factsWith(roles ...string) *Facts {
	f := &Facts{Services: map[string]Service{}}
	for _, role := range roles {
		switch role {
		case "dc":
			f.ProductType = "LanmanNT"
			f.NTDS = true
			f.Services["NTDS"] = service(serviceStartAuto)
			f.Services["Netlogon"] = service(serviceStartAuto)
			f.Shares = append(f.Shares,
				Share{Name: "SYSVOL", Path: `C:\Windows\SYSVOL\sysvol`},
				Share{Name: "NETLOGON", Path: `C:\Windows\SYSVOL\sysvol\corp\scripts`},
			)
		case "web":
			f.IIS = &IISFacts{Registry: true, MajorVersion: 10, ConfigPresent: true}
			f.Services["W3SVC"] = service(serviceStartAuto)
		case "file":
			f.Shares = append(f.Shares,
				Share{Name: "IPC$"},
				Share{Name: "C$", Path: `C:\`},
				Share{Name: "Data", Path: `D:\Shares\Data`},
			)
			f.Services["LanmanServer"] = service(serviceStartAuto)
		case "sql":
			f.SQLInstances = []string{"MSSQLSERVER"}
			f.Services["MSSQLSERVER"] = service(serviceStartAuto)
		case "exchange":
			f.Exchange = "v15"
			f.Services["MSExchangeIS"] = service(serviceStartAuto)
			f.Services["MSExchangeTransport"] = service(serviceStartAuto)
		case "dns":
			f.Services["DNS"] = service(serviceStartAuto)
			f.DNSDirectory = true
		case "dhcp":
			f.Services["DHCPServer"] = service(serviceStartAuto)
			f.DHCPDirectory = true
		}
	}
	return f
}

func roleByName(results []RoleResult, role Role) (RoleResult, bool) {
	for _, result := range results {
		if result.Role == role {
			return result, true
		}
	}
	return RoleResult{}, false
}

func TestClassifyDomainController(t *testing.T) {
	f := factsWith("dc")
	results := Classify(f)
	dc, ok := roleByName(results, RoleDomainController)
	if !ok || dc.Tier != TierConfirmed || dc.Confidence != 1 {
		t.Fatalf("dc = %+v (present=%v), results=%+v", dc, ok, results)
	}
	if _, ok := roleByName(results, RoleFileServer); ok {
		t.Fatalf("SYSVOL/NETLOGON must not make a DC a file server: %+v", results)
	}
}

func TestClassifyWebServer(t *testing.T) {
	f := factsWith("web")
	results := Classify(f)
	web, ok := roleByName(results, RoleWebServer)
	if !ok || web.Tier != TierConfirmed {
		t.Fatalf("web = %+v (present=%v), results=%+v", web, ok, results)
	}
	if len(web.Evidence) != 3 {
		t.Fatalf("evidence = %+v, want registry + config + service", web.Evidence)
	}
}

func TestClassifyFileServerUsesCustomSharesOnly(t *testing.T) {
	f := factsWith("file")
	results := Classify(f)
	file, ok := roleByName(results, RoleFileServer)
	if !ok || file.Tier != TierConfirmed {
		t.Fatalf("file = %+v (present=%v), results=%+v", file, ok, results)
	}
	detail := file.Evidence[0].Detail
	if detail != "non-default SMB share(s): Data" {
		t.Fatalf("share detail = %q, want only the custom share", detail)
	}
}

func TestClassifyDatabaseAndMail(t *testing.T) {
	f := factsWith("sql", "exchange")
	results := Classify(f)
	for _, role := range []Role{RoleDatabaseServer, RoleMailServer} {
		result, ok := roleByName(results, role)
		if !ok || result.Tier != TierConfirmed {
			t.Fatalf("%s = %+v (present=%v), results=%+v", role, result, ok, results)
		}
	}
}

func TestClassifyInfrastructureTiers(t *testing.T) {
	f := factsWith("dns", "dhcp")
	results := Classify(f)
	for _, role := range []Role{RoleDNSServer, RoleDHCPServer} {
		result, ok := roleByName(results, role)
		if !ok || result.Tier != TierProbable || result.Confidence != 0.65 {
			t.Fatalf("%s = %+v (present=%v), results=%+v", role, result, ok, results)
		}
	}
	// A probable role is strong enough to name the host after.
	profile := Build(factsWith("dns"), testTime())
	if profile.PrimaryRole != RoleDNSServer {
		t.Fatalf("primary role = %q, want dns_server", profile.PrimaryRole)
	}
}

func TestClassifyWorkstationWithIISKeepsBothFacts(t *testing.T) {
	f := factsWith("web")
	f.ProductType = "WinNT"
	profile := Build(f, testTime())
	if profile.Host.HostClass != HostClassWorkstation {
		t.Fatalf("host class = %q", profile.Host.HostClass)
	}
	if profile.PrimaryRole != RoleWebServer {
		t.Fatalf("primary role = %q, want web_server", profile.PrimaryRole)
	}
}

func TestClassifyNoServerRole(t *testing.T) {
	f := &Facts{
		ProductType: "WinNT",
		Services:    map[string]Service{"LanmanServer": service(serviceStartAuto)},
		Shares: []Share{
			{Name: "IPC$"},
			{Name: "ADMIN$", Path: `C:\Windows`},
			{Name: "C$", Path: `C:\`},
		},
	}
	profile := Build(f, testTime())
	if len(profile.Roles) != 0 {
		t.Fatalf("roles = %+v, want none", profile.Roles)
	}
	if profile.PrimaryRole != "" {
		t.Fatalf("primary role = %q, want empty", profile.PrimaryRole)
	}
}

func TestClassifyPossibleRoleIsNotPrimary(t *testing.T) {
	f := &Facts{
		Services: map[string]Service{
			"Netlogon": service(serviceStartAuto),
		},
		Shares: []Share{
			{Name: "SYSVOL"},
			{Name: "NETLOGON"},
		},
	}
	results := Classify(f)
	dc, ok := roleByName(results, RoleDomainController)
	if !ok || dc.Tier != TierPossible {
		t.Fatalf("dc = %+v (present=%v), results=%+v", dc, ok, results)
	}
	if profile := Build(f, testTime()); profile.PrimaryRole != "" {
		t.Fatalf("primary role = %q, want empty for a possible-only role", profile.PrimaryRole)
	}
}

func TestClassifyTieBreakOrder(t *testing.T) {
	f := factsWith("dc", "web")
	results := Classify(f)
	if len(results) < 2 || results[0].Role != RoleDomainController {
		t.Fatalf("tie-break = %+v, want domain_controller first", results)
	}
}

func TestClassifyNil(t *testing.T) {
	if got := Classify(nil); len(got) != 0 {
		t.Fatalf("Classify(nil) = %+v", got)
	}
}
