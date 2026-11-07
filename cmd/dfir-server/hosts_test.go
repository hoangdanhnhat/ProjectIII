package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.com/dfir-collector/internal/protocol"
)

type inventoryClient struct {
	t   *testing.T
	url string
}

func newInventoryClient(t *testing.T, s *server) (*inventoryClient, func()) {
	t.Helper()
	ts := httptest.NewServer(s.routes())
	return &inventoryClient{t: t, url: ts.URL}, ts.Close
}

func (c *inventoryClient) do(method, path, token, hostID string, body any) *http.Response {
	c.t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.url+path, reader)
	if err != nil {
		c.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if hostID != "" {
		req.Header.Set("X-Host-ID", hostID)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

func decodeHost(t *testing.T, resp *http.Response) protocol.Host {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
	var host protocol.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}
	return host
}

func heartbeatBody(name, hostClass string, roles []protocol.HostRoleSummary) protocol.HostReport {
	checked := time.Now().UTC().Add(-time.Minute)
	return protocol.HostReport{
		Hostname: name,
		OS: protocol.HostOS{
			Name:        "Windows Server 2022 Standard",
			Build:       "20348.1000",
			ProductType: "ServerNT",
			HostClass:   hostClass,
			Platform:    "windows",
			Arch:        "amd64",
		},
		AutoRoles:     roles,
		RoleCheckedAt: &checked,
		AgentVersion:  "0.1.0",
	}
}

func TestInventoryHeartbeatAndManualOverride(t *testing.T) {
	dir := t.TempDir()
	s, err := newServerWithHosts(dir, []string{"lab", "win-web01"}, "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	client, closeServer := newInventoryClient(t, s)
	defer closeServer()

	resp := client.do("POST", "/v1/agent/host", "agent-secret", "win-web01", heartbeatBody(
		"WIN-WEB01", "server",
		[]protocol.HostRoleSummary{{Role: "web_server", Confidence: 1, Tier: "confirmed"}},
	))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: HTTP %d", resp.StatusCode)
	}
	var assignment protocol.HostAssignment
	if err := json.NewDecoder(resp.Body).Decode(&assignment); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if assignment.HostID != "win-web01" || len(assignment.ManualRoles) != 0 || assignment.RoleRevision != 0 {
		t.Fatalf("assignment = %+v", assignment)
	}

	resp = client.do("GET", "/v1/hosts", "operator-secret", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: HTTP %d", resp.StatusCode)
	}
	var list struct {
		Hosts []protocol.Host `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(list.Hosts) != 2 {
		t.Fatalf("hosts = %+v", list.Hosts)
	}
	var web protocol.Host
	for _, host := range list.Hosts {
		if host.ID == "win-web01" {
			web = host
		}
	}
	if web.Hostname != "WIN-WEB01" || web.Status != hostStatusOnline ||
		len(web.AutoRoles) != 1 || web.EffectiveRoles[0] != "web_server" {
		t.Fatalf("web host = %+v", web)
	}

	resp = client.do("PUT", "/v1/hosts/win-web01/roles", "operator-secret", "", map[string]any{
		"roles": []string{"workstation", "web_server"},
		"note":  "operator confirmed",
	})
	host := decodeHost(t, resp)
	if host.RoleSource != "manual" || host.RoleRevision != 1 ||
		strings.Join(host.EffectiveRoles, ",") != "web_server,workstation" ||
		host.ManualNote != "operator confirmed" {
		t.Fatalf("manual host = %+v", host)
	}

	// The agent acknowledges revision 1 and receives the override.
	resp = client.do("POST", "/v1/agent/host", "agent-secret", "win-web01", protocol.HostReport{
		Hostname:            "WIN-WEB01",
		AppliedRoleRevision: 1,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ack heartbeat: HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&assignment); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Join(assignment.ManualRoles, ",") != "web_server,workstation" || assignment.RoleRevision != 1 {
		t.Fatalf("ack assignment = %+v", assignment)
	}

	// A partial OS in a later heartbeat must not erase the earlier values.
	host = decodeHost(t, client.do("GET", "/v1/hosts/win-web01", "operator-secret", "", nil))
	if host.OS.Name != "Windows Server 2022 Standard" || host.OS.Build != "20348.1000" {
		t.Fatalf("OS was not preserved: %+v", host.OS)
	}

	// Restart: manual override and revision survive.
	s2, err := newServerWithHosts(dir, []string{"lab", "win-web01"}, "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	client2, closeServer2 := newInventoryClient(t, s2)
	defer closeServer2()
	host = decodeHost(t, client2.do("GET", "/v1/hosts/win-web01", "operator-secret", "", nil))
	if host.RoleSource != "manual" || host.RoleRevision != 1 || host.AppliedRoleRevision != 1 {
		t.Fatalf("reloaded host = %+v", host)
	}

	// Reset returns to the last automatic result.
	host = decodeHost(t, client2.do("DELETE", "/v1/hosts/win-web01/roles", "operator-secret", "", nil))
	if host.RoleSource != "auto" || host.RoleRevision != 2 ||
		strings.Join(host.EffectiveRoles, ",") != "web_server" {
		t.Fatalf("reset host = %+v", host)
	}

	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "host.roles") || !strings.Contains(string(audit), "host.roles.reset") {
		t.Fatalf("audit = %s", audit)
	}
}

func TestInventoryValidationAndRouting(t *testing.T) {
	dir := t.TempDir()
	s, err := newServerWithHosts(dir, []string{"lab", "win-web01"}, "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	client, closeServer := newInventoryClient(t, s)
	defer closeServer()

	// Unknown agent host is rejected before touching the inventory.
	resp := client.do("POST", "/v1/agent/host", "agent-secret", "unknown", heartbeatBody("x", "server", nil))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown host heartbeat: HTTP %d", resp.StatusCode)
	}

	// Unknown and empty roles are rejected.
	resp = client.do("PUT", "/v1/hosts/win-web01/roles", "operator-secret", "", map[string]any{
		"roles": []string{"not_a_role"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid role: HTTP %d", resp.StatusCode)
	}
	resp = client.do("PUT", "/v1/hosts/win-web01/roles", "operator-secret", "", map[string]any{
		"roles": []string{},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty roles: HTTP %d", resp.StatusCode)
	}

	// Jobs are routed to the requesting host.
	resp = client.do("POST", "/v1/jobs", "operator-secret", "", map[string]any{
		"host_id": "win-web01", "scenario": "netstat.v1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create for second host: HTTP %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = client.do("GET", "/v1/agent/jobs/next", "agent-secret", "lab", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("lab got another host's job: HTTP %d", resp.StatusCode)
	}
	resp = client.do("GET", "/v1/agent/jobs/next", "agent-secret", "win-web01", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("win-web01 did not get its job: HTTP %d", resp.StatusCode)
	}

	// Meta exposes the host list and role vocabulary.
	resp = client.do("GET", "/v1/meta", "operator-secret", "", nil)
	var meta struct {
		HostID string   `json:"host_id"`
		Hosts  []string `json:"hosts"`
		Roles  []string `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if meta.HostID != "lab" || len(meta.Hosts) != 2 || len(meta.Roles) == 0 {
		t.Fatalf("meta = %+v", meta)
	}
}

func TestWildcardAcceptsMachineHostname(t *testing.T) {
	dir := t.TempDir()
	s, err := newServerWithPolicy(dir, nil, true, "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	client, closeServer := newInventoryClient(t, s)
	defer closeServer()

	// The agent sends its real hostname; the server normalizes it.
	resp := client.do("POST", "/v1/agent/host", "agent-secret", "WIN-WEB01", heartbeatBody(
		"WIN-WEB01", "server",
		[]protocol.HostRoleSummary{{Role: "web_server", Confidence: 1, Tier: "confirmed"}},
	))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat: HTTP %d", resp.StatusCode)
	}
	resp.Body.Close()

	host := decodeHost(t, client.do("GET", "/v1/hosts/win-web01", "operator-secret", "", nil))
	if host.ID != "win-web01" || host.Hostname != "WIN-WEB01" || host.Status != hostStatusOnline {
		t.Fatalf("host = %+v", host)
	}

	resp = client.do("GET", "/v1/meta", "operator-secret", "", nil)
	var meta struct {
		HostID string   `json:"host_id"`
		Hosts  []string `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if meta.HostID != "win-web01" || len(meta.Hosts) != 1 || meta.Hosts[0] != "win-web01" {
		t.Fatalf("meta = %+v", meta)
	}

	// Jobs may target a machine only after it has checked in.
	resp = client.do("POST", "/v1/jobs", "operator-secret", "", map[string]any{
		"host_id": "WIN-WEB01", "scenario": "netstat.v1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create for registered host: HTTP %d", resp.StatusCode)
	}
	var job protocol.Job
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if job.HostID != "win-web01" {
		t.Fatalf("job host = %q", job.HostID)
	}
	resp = client.do("POST", "/v1/jobs", "operator-secret", "", map[string]any{
		"host_id": "unknown-host", "scenario": "netstat.v1",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create for unknown host: HTTP %d", resp.StatusCode)
	}

	// An invalid X-Host-ID is rejected before it creates inventory.
	resp = client.do("POST", "/v1/agent/host", "agent-secret", "bad host", heartbeatBody("x", "server", nil))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid host ID: HTTP %d", resp.StatusCode)
	}
}

func TestAllowlistRejectsHostnameOutsideList(t *testing.T) {
	dir := t.TempDir()
	s, err := newServerWithHosts(dir, []string{"lab"}, "operator-secret", "agent-secret")
	if err != nil {
		t.Fatal(err)
	}
	client, closeServer := newInventoryClient(t, s)
	defer closeServer()
	resp := client.do("POST", "/v1/agent/host", "agent-secret", "win-web01", heartbeatBody("WIN-WEB01", "server", nil))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlist hostname: HTTP %d, want 403", resp.StatusCode)
	}
}

func TestInventoryStatusThresholds(t *testing.T) {
	now := time.Now().UTC()
	host := &protocol.Host{}
	if got := computeHostStatus(host, now); got != hostStatusNeverSeen {
		t.Fatalf("never seen = %q", got)
	}
	recent := now.Add(-time.Minute)
	host.LastSeenAt = &recent
	if got := computeHostStatus(host, now); got != hostStatusOnline {
		t.Fatalf("online = %q", got)
	}
	old := now.Add(-2 * time.Hour)
	host.LastSeenAt = &old
	if got := computeHostStatus(host, now); got != hostStatusStale {
		t.Fatalf("stale = %q", got)
	}
	ancient := now.Add(-48 * time.Hour)
	host.LastSeenAt = &ancient
	if got := computeHostStatus(host, now); got != hostStatusOffline {
		t.Fatalf("offline = %q", got)
	}
}
