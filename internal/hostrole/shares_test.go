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

func TestHasShareIsCaseInsensitive(t *testing.T) {
	if !hasShare([]Share{{Name: "sysvol"}}, "SYSVOL") {
		t.Fatal("expected case-insensitive match")
	}
}
