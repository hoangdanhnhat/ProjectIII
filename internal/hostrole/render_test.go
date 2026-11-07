package hostrole

import (
	"strings"
	"testing"
	"time"
)

func testTime() time.Time {
	return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
}

func TestBuildProfile(t *testing.T) {
	f := factsWith("web")
	f.ProductType = "ServerNT"
	f.Hostname = "WEB01"
	f.OSName = "Windows Server 2022 Standard"
	f.OSBuild = "20348.1000"
	profile := Build(f, testTime())

	if profile.SchemaVersion != 1 || profile.Method != method {
		t.Fatalf("profile header = %+v", profile)
	}
	if !profile.GeneratedAt.Equal(testTime()) {
		t.Fatalf("generated_at = %v", profile.GeneratedAt)
	}
	if profile.Host.Hostname != "WEB01" || profile.Host.HostClass != HostClassServer {
		t.Fatalf("host = %+v", profile.Host)
	}
	if profile.PrimaryRole != RoleWebServer {
		t.Fatalf("primary_role = %q", profile.PrimaryRole)
	}
}

func TestRenderIsDeterministicAndParsable(t *testing.T) {
	f := factsWith("dc", "file", "dns")
	f.ProbeErrors = []ProbeError{
		{Source: "z", Detail: "last"},
		{Source: "a", Detail: "first"},
		{Source: "a", Detail: "first"},
	}
	profile := Build(f, testTime())
	first := Render(profile)
	second := Render(profile)
	if string(first) != string(second) {
		t.Fatal("two renders of the same profile differ")
	}
	if strings.Index(string(first), `"source": "a"`) > strings.Index(string(first), `"source": "z"`) {
		t.Fatal("probe errors are not sorted")
	}
	if strings.Count(string(first), `"source": "a"`) != 1 {
		t.Fatal("duplicate probe errors were not removed")
	}

	parsed, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PrimaryRole != RoleDomainController || len(parsed.Roles) != 3 {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestRenderEmptyRolesIsArray(t *testing.T) {
	profile := Build(&Facts{Services: map[string]Service{}}, testTime())
	data := string(Render(profile))
	if !strings.Contains(data, `"roles": []`) {
		t.Fatalf("empty roles must render as []:\n%s", data)
	}
	if strings.Contains(data, `"primary_role"`) {
		t.Fatalf("empty primary_role must be omitted:\n%s", data)
	}
}

func TestParseRejectsUnknownSchema(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version": 2, "roles": []}`)); err == nil {
		t.Fatal("expected an unknown schema error")
	}
}
