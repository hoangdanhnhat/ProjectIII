//go:build linux || windows

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"example.com/dfir-collector/internal/hostrole"
	"example.com/dfir-collector/internal/protocol"
)

type fakeRoleSource struct {
	calls int
	facts *hostrole.Facts
	err   error
}

func (f *fakeRoleSource) Facts(context.Context) (*hostrole.Facts, error) {
	f.calls++
	return f.facts, f.err
}

func roleFacts() *hostrole.Facts {
	return &hostrole.Facts{
		Hostname:    "WIN-WEB01",
		ProductType: "ServerNT",
		OSName:      "Windows Server 2022 Standard",
		OSBuild:     "20348.1000",
		Services: map[string]hostrole.Service{
			"W3SVC": {Present: true, Start: 2, HasStart: true},
		},
		IIS: &hostrole.IISFacts{Registry: true, MajorVersion: 10, ConfigPresent: true},
	}
}

type heartbeatServer struct {
	replies  []protocol.HostAssignment
	requests int
	reports  []protocol.HostReport
}

func (h *heartbeatServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent/host" {
			http.NotFound(w, r)
			return
		}
		var report protocol.HostReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, "bad report", 400)
			return
		}
		h.requests++
		h.reports = append(h.reports, report)
		reply := protocol.HostAssignment{HostID: "h", ServerTime: time.Now().UTC()}
		if len(h.replies) > 0 {
			index := h.requests - 1
			if index >= len(h.replies) {
				index = len(h.replies) - 1
			}
			reply = h.replies[index]
		}
		_ = json.NewEncoder(w).Encode(reply)
	})
}

func newInventoryAgent(t *testing.T, url, statePath string, source hostrole.Source, now func() time.Time) *Agent {
	t.Helper()
	return New(Options{
		ServerURL:         url,
		HostID:            "h",
		Token:             "token",
		StatePath:         statePath,
		HeartbeatInterval: time.Hour,
		RoleInterval:      time.Hour,
		RoleSource:        source,
		Now:               now,
	})
}

func TestStateRoundTripAndHostMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	checked := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	state := &State{
		HostID:        "h",
		Hostname:      "WIN-WEB01",
		Roles:         []string{"web_server"},
		Source:        "manual",
		Revision:      3,
		AutoCheckedAt: &checked,
	}
	if err := saveState(path, state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode = %v", info.Mode().Perm())
	}
	loaded, err := loadState(path, "h")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.Source != "manual" || loaded.Revision != 3 ||
		len(loaded.Roles) != 1 || loaded.Roles[0] != "web_server" {
		t.Fatalf("loaded = %+v", loaded)
	}
	other, err := loadState(path, "other")
	if err != nil || other != nil {
		t.Fatalf("host mismatch = %+v, %v", other, err)
	}
}

func TestManualOverrideSkipsDetection(t *testing.T) {
	hb := &heartbeatServer{replies: []protocol.HostAssignment{
		{HostID: "h", ManualRoles: []string{"workstation"}, RoleRevision: 1},
	}}
	ts := httptest.NewServer(hb.handler())
	defer ts.Close()
	source := &fakeRoleSource{facts: roleFacts()}
	now := func() time.Time { return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC) }
	a := newInventoryAgent(t, ts.URL, filepath.Join(t.TempDir(), "state.json"), source, now)

	a.maintainHost(context.Background())

	if source.calls != 0 {
		t.Fatalf("role detection ran %d times under a manual override", source.calls)
	}
	if a.state == nil || a.state.Source != "manual" || a.state.Revision != 1 ||
		len(a.state.Roles) != 1 || a.state.Roles[0] != "workstation" {
		t.Fatalf("state = %+v", a.state)
	}
	loaded, err := loadState(a.statePath, "h")
	if err != nil || loaded == nil || loaded.Source != "manual" {
		t.Fatalf("persisted state = %+v, %v", loaded, err)
	}
}

func TestResetTriggersImmediateDetection(t *testing.T) {
	hb := &heartbeatServer{replies: []protocol.HostAssignment{
		{HostID: "h", RoleRevision: 2},
	}}
	ts := httptest.NewServer(hb.handler())
	defer ts.Close()
	statePath := filepath.Join(t.TempDir(), "state.json")
	checked := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	if err := saveState(statePath, &State{
		HostID:        "h",
		Roles:         []string{"workstation"},
		Source:        "manual",
		Revision:      1,
		AutoCheckedAt: &checked,
	}); err != nil {
		t.Fatal(err)
	}
	source := &fakeRoleSource{facts: roleFacts()}
	now := func() time.Time { return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC) }
	a := newInventoryAgent(t, ts.URL, statePath, source, now)

	a.maintainHost(context.Background())

	if source.calls != 1 {
		t.Fatalf("detection calls = %d, want 1", source.calls)
	}
	if a.state.Source != "auto" || a.state.Revision != 2 ||
		len(a.state.Roles) != 1 || a.state.Roles[0] != "web_server" {
		t.Fatalf("state = %+v", a.state)
	}
	if hb.requests < 2 {
		t.Fatalf("heartbeats = %d, want initial + role report", hb.requests)
	}
}

func TestHourlyDetectionCadence(t *testing.T) {
	hb := &heartbeatServer{}
	ts := httptest.NewServer(hb.handler())
	defer ts.Close()
	nowValue := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return nowValue }
	source := &fakeRoleSource{facts: roleFacts()}
	a := newInventoryAgent(t, ts.URL, filepath.Join(t.TempDir(), "state.json"), source, now)

	a.maintainHost(context.Background())
	if source.calls != 1 {
		t.Fatalf("initial detection = %d", source.calls)
	}

	nowValue = nowValue.Add(30 * time.Minute)
	a.nextHeartbeat = time.Time{}
	a.maintainHost(context.Background())
	if source.calls != 1 {
		t.Fatalf("detection ran before the hourly interval: %d", source.calls)
	}

	nowValue = nowValue.Add(31 * time.Minute)
	a.nextHeartbeat = time.Time{}
	a.maintainHost(context.Background())
	if source.calls != 2 {
		t.Fatalf("detection did not run after the hourly interval: %d", source.calls)
	}
}

func TestHeartbeatFailureStillStoresLocalRoles(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer ts.Close()
	source := &fakeRoleSource{facts: roleFacts()}
	now := func() time.Time { return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC) }
	a := newInventoryAgent(t, ts.URL, filepath.Join(t.TempDir(), "state.json"), source, now)

	a.maintainHost(context.Background())

	if source.calls != 1 {
		t.Fatalf("detection calls = %d", source.calls)
	}
	loaded, err := loadState(a.statePath, "h")
	if err != nil || loaded == nil || len(loaded.Roles) != 1 || loaded.Roles[0] != "web_server" {
		t.Fatalf("local state = %+v, %v", loaded, err)
	}
}
