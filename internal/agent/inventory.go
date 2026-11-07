package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"time"

	"example.com/dfir-collector/internal/hostrole"
	"example.com/dfir-collector/internal/protocol"
)

func (a *Agent) loadInventoryState() {
	state, err := loadState(a.statePath, a.host)
	if err != nil {
		log.Printf("inventory state: %v", err)
	}
	a.state = state
	if a.state == nil {
		a.state = a.freshState()
	}
	a.stateLoaded = true
}

func (a *Agent) freshState() *State {
	hostname, _ := os.Hostname()
	return &State{
		SchemaVersion: stateSchemaVersion,
		HostID:        a.host,
		Hostname:      hostname,
		OS: protocol.HostOS{
			Platform: runtime.GOOS,
			Arch:     runtime.GOARCH,
		},
		Roles:     []string{},
		Source:    "auto",
		AutoRoles: []protocol.HostRoleSummary{},
	}
}

// maintainHost keeps the inventory fresh. The first heartbeat is sent before
// any automatic detection so a manual override already stored on the server
// takes effect without a needless registry scan.
func (a *Agent) maintainHost(ctx context.Context) {
	if !a.stateLoaded || a.state == nil {
		a.loadInventoryState()
	}
	now := a.now()
	if !a.nextHeartbeat.IsZero() && now.Before(a.nextHeartbeat) {
		return
	}
	a.nextHeartbeat = now.Add(a.heartbeatInterval)

	sent := false
	if !a.contacted {
		sent = true
		if a.sendHeartbeat(ctx) {
			a.contacted = true
		}
	}

	if !a.stateManual() && a.roleCheckDue(now) {
		a.detectRoles(ctx, now)
		if a.sendHeartbeat(ctx) {
			a.contacted = true
		}
		return
	}
	if !sent {
		if a.sendHeartbeat(ctx) {
			a.contacted = true
		}
	}
}

func (a *Agent) stateManual() bool {
	return a.state != nil && a.state.Source == "manual" && len(a.state.Roles) > 0
}

func (a *Agent) roleCheckDue(now time.Time) bool {
	if a.state == nil || a.state.AutoCheckedAt == nil {
		return true
	}
	return !now.Before(a.state.AutoCheckedAt.Add(a.roleInterval))
}

func (a *Agent) detectRoles(ctx context.Context, now time.Time) {
	checked := now.UTC()
	profile, err := hostrole.Detect(ctx, a.roleSource)
	a.state.AutoCheckedAt = &checked
	if err != nil {
		a.state.RoleError = err.Error()
		a.saveInventoryState()
		return
	}
	a.state.RoleError = ""
	if profile.Host.Hostname != "" {
		a.state.Hostname = profile.Host.Hostname
	}
	mergeOS(&a.state.OS, protocol.HostOS{
		Name:        profile.Host.OSName,
		Build:       profile.Host.OSBuild,
		ProductType: profile.Host.ProductType,
		HostClass:   profile.Host.HostClass,
		Platform:    runtime.GOOS,
		Arch:        runtime.GOARCH,
	})
	a.state.AutoRoles = roleSummaries(profile.Roles)
	if !a.stateManual() {
		a.state.Roles = roleIDs(a.state.AutoRoles)
	}
	a.saveInventoryState()
}

// roleSummaries drops "possible" roles from the inventory: the host_role
// artifact keeps the full evidence, but the inventory should not present weak
// signals as established roles.
func mergeOS(dst *protocol.HostOS, src protocol.HostOS) {
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

func roleSummaries(results []hostrole.RoleResult) []protocol.HostRoleSummary {
	out := make([]protocol.HostRoleSummary, 0, len(results))
	for _, result := range results {
		if result.Tier == hostrole.TierPossible {
			continue
		}
		out = append(out, protocol.HostRoleSummary{
			Role:       string(result.Role),
			Confidence: result.Confidence,
			Tier:       string(result.Tier),
		})
	}
	return out
}

func roleIDs(roles []protocol.HostRoleSummary) []string {
	if len(roles) == 0 {
		return []string{}
	}
	order := hostrole.AllRoles()
	rank := make(map[string]int, len(order))
	for i, role := range order {
		rank[string(role)] = i
	}
	ids := make([]string, 0, len(roles))
	for _, role := range roles {
		ids = append(ids, role.Role)
	}
	sort.SliceStable(ids, func(i, j int) bool {
		if rank[ids[i]] != rank[ids[j]] {
			return rank[ids[i]] < rank[ids[j]]
		}
		return ids[i] < ids[j]
	})
	return ids
}

func (a *Agent) hostReport() protocol.HostReport {
	return protocol.HostReport{
		Hostname:            a.state.Hostname,
		OS:                  a.state.OS,
		AutoRoles:           a.state.AutoRoles,
		RoleCheckedAt:       a.state.AutoCheckedAt,
		RoleError:           a.state.RoleError,
		AppliedRoleRevision: a.state.Revision,
		AgentVersion:        a.version,
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) bool {
	body, err := json.Marshal(a.hostReport())
	if err != nil {
		log.Printf("inventory heartbeat encode: %v", err)
		return false
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.base+"/v1/agent/host", bytes.NewReader(body))
	if err != nil {
		log.Printf("inventory heartbeat: %v", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("X-Host-ID", a.host)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("inventory heartbeat: %v", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("inventory heartbeat: HTTP %d", resp.StatusCode)
		return false
	}
	var assignment protocol.HostAssignment
	if err := json.NewDecoder(resp.Body).Decode(&assignment); err != nil {
		log.Printf("inventory heartbeat decode: %v", err)
		return false
	}
	if a.applyAssignment(assignment) {
		a.saveInventoryState()
	}
	return true
}

func (a *Agent) applyAssignment(assignment protocol.HostAssignment) bool {
	if a.state == nil {
		return false
	}
	changed := false
	if len(assignment.ManualRoles) > 0 {
		roles := append([]string{}, assignment.ManualRoles...)
		if a.state.Source != "manual" || !equalStrings(a.state.Roles, roles) ||
			a.state.Revision != assignment.RoleRevision {
			a.state.Source = "manual"
			a.state.Roles = roles
			a.state.Revision = assignment.RoleRevision
			changed = true
		}
		return changed
	}
	if a.state.Source == "manual" {
		a.state.Source = "auto"
		a.state.Roles = roleIDs(a.state.AutoRoles)
		// Force a fresh detection on the next maintenance pass.
		a.state.AutoCheckedAt = nil
		changed = true
	}
	if assignment.RoleRevision > a.state.Revision {
		a.state.Revision = assignment.RoleRevision
		changed = true
	}
	return changed
}

func (a *Agent) saveInventoryState() {
	if a.state == nil {
		return
	}
	if err := saveState(a.statePath, a.state); err != nil {
		log.Printf("inventory state save: %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
