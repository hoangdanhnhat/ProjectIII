package hostrole

import "testing"

func TestParseShareValue(t *testing.T) {
	share := ParseShareValue("Finance$", []string{
		`CSCFlags=0`,
		`Path=D:\Shares\Finance`,
		`Remark=quarterly reports`,
		`Permissions=`,
	})
	if share.Name != "Finance$" || share.Path != `D:\Shares\Finance` {
		t.Fatalf("share = %+v", share)
	}
}

func TestParseShareValueWithoutPath(t *testing.T) {
	share := ParseShareValue("Data", []string{`Remark=no path here`})
	if share.Name != "Data" || share.Path != "" {
		t.Fatalf("share = %+v", share)
	}
}

func TestIsDefaultShare(t *testing.T) {
	defaults := []string{"IPC$", "ADMIN$", "print$", "C$", "z$", "SYSVOL", "NETLOGON"}
	for _, name := range defaults {
		if !IsDefaultShare(name) {
			t.Errorf("%q should be a default share", name)
		}
	}
	custom := []string{"Data", "Finance$", "Backups", "AB$"}
	for _, name := range custom {
		if IsDefaultShare(name) {
			t.Errorf("%q should be a custom share", name)
		}
	}
}

func TestCustomSharesSortedAndFiltered(t *testing.T) {
	shares := []Share{
		{Name: "zeta", Path: `D:\zeta`},
		{Name: "ADMIN$"},
		{Name: "Alpha", Path: `D:\alpha`},
		{Name: "IPC$"},
		{Name: "beta$", Path: `D:\beta`},
	}
	custom := CustomShares(shares)
	if len(custom) != 3 {
		t.Fatalf("custom shares = %+v", custom)
	}
	want := []string{"Alpha", "beta$", "zeta"}
	for i, name := range want {
		if custom[i].Name != name {
			t.Fatalf("custom[%d] = %q, want %q", i, custom[i].Name, name)
		}
	}
}

func TestHasShareIsCaseInsensitive(t *testing.T) {
	if !hasShare([]Share{{Name: "sysvol"}}, "SYSVOL") {
		t.Fatal("expected case-insensitive match")
	}
}
