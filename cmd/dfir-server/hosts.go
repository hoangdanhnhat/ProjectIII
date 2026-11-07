package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"example.com/dfir-collector/internal/hostrole"
	"example.com/dfir-collector/internal/protocol"
)

const hostSchemaVersion = 1

const (
	hostStatusOnline    = "online"
	hostStatusStale     = "stale"
	hostStatusOffline   = "offline"
	hostStatusNeverSeen = "never_seen"

	onlineWindow = 5 * time.Minute
	staleWindow  = 24 * time.Hour

	maxManualNote = 200
)

// parseHostList turns -hosts into an allowlist or wildcard mode. "*" must be
// used on its own; mixing it with concrete IDs hides mistakes.
func parseHostList(raw string) ([]string, bool, error) {
	var out []string
	seen := make(map[string]bool)
	allowAny := false
	for _, part := range strings.Split(raw, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		if token == "*" {
			allowAny = true
			continue
		}
		id, err := protocol.NormalizeHostID(token)
		if err != nil {
			return nil, false, err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if allowAny && len(out) > 0 {
		return nil, false, fmt.Errorf("host list cannot combine '*' with explicit host IDs")
	}
	return out, allowAny, nil
}

func hostPath(dir, id string) string {
	return filepath.Join(dir, "hosts", id+".json")
}

func newHostRecord(id string, now time.Time) *protocol.Host {
	return &protocol.Host{
		SchemaVersion:  hostSchemaVersion,
		ID:             id,
		AutoRoles:      []protocol.HostRoleSummary{},
		EffectiveRoles: []string{},
		RoleSource:     "auto",
		CreatedAt:      now.UTC(),
		Status:         hostStatusNeverSeen,
	}
}

func loadHosts(dir string, configured []string) (map[string]*protocol.Host, error) {
	hosts := make(map[string]*protocol.Host)
	files, err := filepath.Glob(filepath.Join(dir, "hosts", "*.json"))
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var host protocol.Host
		if err := json.Unmarshal(b, &host); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		normalized, err := protocol.NormalizeHostID(host.ID)
		if err != nil || normalized != host.ID || filepath.Base(file) != host.ID+".json" {
			return nil, fmt.Errorf("invalid host file %s", file)
		}
		if host.SchemaVersion != 0 && host.SchemaVersion != hostSchemaVersion {
			return nil, fmt.Errorf("%s: unsupported schema_version %d", file, host.SchemaVersion)
		}
		normalizeHost(&host, time.Now().UTC())
		hosts[host.ID] = &host
	}
	for _, id := range configured {
		if hosts[id] != nil {
			continue
		}
		host := newHostRecord(id, time.Now().UTC())
		if err := saveHostRecord(dir, host); err != nil {
			return nil, err
		}
		hosts[id] = host
	}
	return hosts, nil
}

func saveHostRecord(dir string, host *protocol.Host) error {
	b, err := json.MarshalIndent(host, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Join(dir, "hosts"), ".host-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), hostPath(dir, host.ID))
}

// normalizeHost repairs slices, re-derives effective roles and refreshes the
// computed status. It is run after loading and before every response.
func normalizeHost(host *protocol.Host, now time.Time) {
	if host.SchemaVersion == 0 {
		host.SchemaVersion = hostSchemaVersion
	}
	if host.AutoRoles == nil {
		host.AutoRoles = []protocol.HostRoleSummary{}
	}
	host.ManualRoles = validRoleIDs(host.ManualRoles)
	if len(host.ManualRoles) == 0 {
		host.ManualNote = ""
		host.ManualUpdatedAt = nil
	}
	syncEffectiveRoles(host)
	host.Status = computeHostStatus(host, now)
}

func syncEffectiveRoles(host *protocol.Host) {
	if len(host.ManualRoles) > 0 {
		host.RoleSource = "manual"
		host.EffectiveRoles = append([]string{}, host.ManualRoles...)
		return
	}
	host.RoleSource = "auto"
	ids := make([]string, 0, len(host.AutoRoles))
	for _, role := range host.AutoRoles {
		ids = append(ids, role.Role)
	}
	host.EffectiveRoles = sortRoleIDs(ids)
}

func computeHostStatus(host *protocol.Host, now time.Time) string {
	if host.LastSeenAt == nil {
		return hostStatusNeverSeen
	}
	age := now.Sub(*host.LastSeenAt)
	switch {
	case age <= onlineWindow:
		return hostStatusOnline
	case age <= staleWindow:
		return hostStatusStale
	default:
		return hostStatusOffline
	}
}

func roleRank(role string) int {
	for i, candidate := range hostrole.AllRoles() {
		if string(candidate) == role {
			return i
		}
	}
	return len(hostrole.AllRoles())
}

// validRoleIDs drops role identifiers that are no longer in the vocabulary,
// so a removed role (for example file_server) cannot keep a manual override
// alive after a server upgrade.
func validRoleIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if hostrole.ValidRole(hostrole.Role(id)) {
			out = append(out, id)
		}
	}
	return sortRoleIDs(out)
}

func sortRoleIDs(ids []string) []string {
	if len(ids) == 0 {
		return []string{}
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if roleRank(out[i]) != roleRank(out[j]) {
			return roleRank(out[i]) < roleRank(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

func canonicalRoles(ids []string) ([]string, error) {
	roles := sortRoleIDs(ids)
	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role is required")
	}
	for _, role := range roles {
		if !hostrole.ValidRole(hostrole.Role(role)) {
			return nil, fmt.Errorf("unknown role %q", role)
		}
	}
	return roles, nil
}

func normalizeAutoRoles(roles []protocol.HostRoleSummary) []protocol.HostRoleSummary {
	if len(roles) == 0 {
		return []protocol.HostRoleSummary{}
	}
	best := make(map[string]protocol.HostRoleSummary, len(roles))
	for _, role := range roles {
		if !hostrole.ValidRole(hostrole.Role(role.Role)) {
			continue
		}
		if role.Confidence < 0 {
			role.Confidence = 0
		} else if role.Confidence > 1 {
			role.Confidence = 1
		}
		current, ok := best[role.Role]
		if !ok || role.Confidence > current.Confidence {
			best[role.Role] = role
		}
	}
	out := make([]protocol.HostRoleSummary, 0, len(best))
	for _, role := range best {
		out = append(out, role)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return roleRank(out[i].Role) < roleRank(out[j].Role)
	})
	return out
}

func (s *server) hostsList(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	hosts := make([]*protocol.Host, 0, len(s.hosts))
	for _, host := range s.hosts {
		normalizeHost(host, now)
		hosts = append(hosts, host)
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if strings.ToLower(hosts[i].Hostname) != strings.ToLower(hosts[j].Hostname) {
			return strings.ToLower(hosts[i].Hostname) < strings.ToLower(hosts[j].Hostname)
		}
		return hosts[i].ID < hosts[j].ID
	})
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

func (s *server) hostGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathHostID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	host := s.hosts[id]
	if host == nil {
		http.NotFound(w, r)
		return
	}
	normalizeHost(host, now)
	s.audit("host.view", host.ID, "inventory")
	writeJSON(w, http.StatusOK, host)
}

func (s *server) hostRolesPUT(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Roles []string `json:"roles"`
		Note  string   `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	roles, err := canonicalRoles(req.Roles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(req.Note)
	if len([]rune(note)) > maxManualNote {
		http.Error(w, "note is too long", http.StatusBadRequest)
		return
	}
	id, ok := pathHostID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	host := s.hosts[id]
	if host == nil {
		http.NotFound(w, r)
		return
	}
	host.ManualRoles = roles
	host.ManualNote = note
	host.ManualUpdatedAt = &now
	host.RoleRevision++
	syncEffectiveRoles(host)
	host.Status = computeHostStatus(host, now)
	if err := saveHostRecord(s.dir, host); err != nil {
		http.Error(w, "storage failure", http.StatusInternalServerError)
		return
	}
	s.audit("host.roles", host.ID, "manual: "+strings.Join(roles, ","))
	writeJSON(w, http.StatusOK, host)
}

func (s *server) hostRolesDELETE(w http.ResponseWriter, r *http.Request) {
	id, ok := pathHostID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	host := s.hosts[id]
	if host == nil {
		http.NotFound(w, r)
		return
	}
	if len(host.ManualRoles) > 0 {
		host.ManualRoles = nil
		host.ManualNote = ""
		host.ManualUpdatedAt = &now
		host.RoleRevision++
		syncEffectiveRoles(host)
		host.Status = computeHostStatus(host, now)
		if err := saveHostRecord(s.dir, host); err != nil {
			http.Error(w, "storage failure", http.StatusInternalServerError)
			return
		}
		s.audit("host.roles.reset", host.ID, "automatic")
	} else {
		normalizeHost(host, now)
	}
	writeJSON(w, http.StatusOK, host)
}

func (s *server) agentHost(w http.ResponseWriter, r *http.Request) {
	var report protocol.HostReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&report); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	hostID := requestHostID(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	host := s.hosts[hostID]
	if host == nil {
		host = newHostRecord(hostID, now)
		s.hosts[hostID] = host
	}
	if report.Hostname != "" {
		host.Hostname = strings.TrimSpace(report.Hostname)
	}
	mergeHostOS(&host.OS, report.OS)
	if host.FirstSeenAt == nil {
		first := now
		host.FirstSeenAt = &first
	}
	host.LastSeenAt = &now
	if report.AgentVersion != "" {
		host.AgentVersion = strings.TrimSpace(report.AgentVersion)
	}
	if report.AppliedRoleRevision > host.AppliedRoleRevision {
		host.AppliedRoleRevision = report.AppliedRoleRevision
	}
	if report.RoleCheckedAt != nil {
		if host.RoleCheckedAt == nil || !report.RoleCheckedAt.Before(*host.RoleCheckedAt) {
			checked := report.RoleCheckedAt.UTC()
			host.AutoRoles = normalizeAutoRoles(report.AutoRoles)
			host.RoleCheckedAt = &checked
			host.RoleError = strings.TrimSpace(report.RoleError)
		}
	} else if report.RoleError != "" {
		host.RoleError = strings.TrimSpace(report.RoleError)
	}
	syncEffectiveRoles(host)
	host.Status = computeHostStatus(host, now)
	if err := saveHostRecord(s.dir, host); err != nil {
		http.Error(w, "storage failure", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, protocol.HostAssignment{
		HostID:       host.ID,
		ManualRoles:  append([]string{}, host.ManualRoles...),
		RoleRevision: host.RoleRevision,
		ServerTime:   now,
	})
}

// mergeHostOS preserves previously reported values when a heartbeat carries a
// partial OS (for example the agent's first contact before role detection).
func mergeHostOS(dst *protocol.HostOS, src protocol.HostOS) {
	if src.Name != "" {
		dst.Name = src.Name
	}
	if src.Build != "" {
		dst.Build = src.Build
	}
	if src.ProductType != "" {
		dst.ProductType = src.ProductType
	}
	if src.HostClass != "" {
		dst.HostClass = src.HostClass
	}
	if src.Platform != "" {
		dst.Platform = src.Platform
	}
	if src.Arch != "" {
		dst.Arch = src.Arch
	}
}

// inventoryHostIDs returns the IDs of machines that have an inventory
// record. The caller holds s.mu.
func (s *server) inventoryHostIDs() []string {
	hosts := make([]string, 0, len(s.hosts))
	for id := range s.hosts {
		hosts = append(hosts, id)
	}
	slices.Sort(hosts)
	return hosts
}

// requestHostID returns the normalized X-Host-ID. auth has already validated
// it, so an empty result is only possible on a programming error.
func requestHostID(r *http.Request) string {
	id, _ := protocol.NormalizeHostID(r.Header.Get("X-Host-ID"))
	return id
}

func pathHostID(r *http.Request) (string, bool) {
	id, err := protocol.NormalizeHostID(r.PathValue("id"))
	return id, err == nil
}
