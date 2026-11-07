package protocol

import "testing"

func TestNormalizeHostID(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"WIN-WEB01", "win-web01"},
		{"  lab-ubuntu  ", "lab-ubuntu"},
		{"host.example.com.", "host.example.com"},
		{"DC01", "dc01"},
	}
	for _, tc := range cases {
		got, err := NormalizeHostID(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("NormalizeHostID(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
		}
	}
}

func TestNormalizeHostIDRejectsInvalid(t *testing.T) {
	for _, raw := range []string{"", "  ", "bad host", "-leading", ".leading", "a/b", "ümlaut", string(make([]byte, 65))} {
		if _, err := NormalizeHostID(raw); err == nil {
			t.Fatalf("NormalizeHostID(%q) succeeded, want error", raw)
		}
	}
}

func TestValidHostID(t *testing.T) {
	if !ValidHostID("Win-Web01") {
		t.Fatal("case-insensitive host ID should be valid")
	}
	if ValidHostID("no spaces") {
		t.Fatal("host ID with a space should be invalid")
	}
}
