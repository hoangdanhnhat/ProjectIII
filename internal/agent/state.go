package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"example.com/dfir-collector/internal/protocol"
)

const stateSchemaVersion = 1

// State is the small local cache the agent keeps between restarts. The server
// remains authoritative for manual overrides; this file lets the agent keep
// applying the last known assignment while offline.
type State struct {
	SchemaVersion int                        `json:"schema_version"`
	HostID        string                     `json:"host_id"`
	Hostname      string                     `json:"hostname,omitempty"`
	OS            protocol.HostOS            `json:"os"`
	Roles         []string                   `json:"roles"`
	Source        string                     `json:"source"` // auto | manual
	Revision      int                        `json:"revision"`
	AutoRoles     []protocol.HostRoleSummary `json:"auto_roles,omitempty"`
	AutoCheckedAt *time.Time                 `json:"auto_checked_at,omitempty"`
	RoleError     string                     `json:"role_error,omitempty"`
	UpdatedAt     time.Time                  `json:"updated_at"`
}

// DefaultStatePath returns the platform default for the local role cache.
func DefaultStatePath() string {
	if runtime.GOOS == "windows" {
		if dir := os.Getenv("ProgramData"); dir != "" {
			return filepath.Join(dir, "dfir-agent", "host_state.json")
		}
		return `C:\ProgramData\dfir-agent\host_state.json`
	}
	return "/var/lib/dfir-agent/host_state.json"
}

func loadState(path, hostID string) (*State, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, errors.New("state file is a symlink or reparse point")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("state decode: %w", err)
	}
	if state.SchemaVersion != stateSchemaVersion || state.HostID != hostID {
		// A copied or stale state file must not change this host's roles.
		return nil, nil
	}
	if state.Roles == nil {
		state.Roles = []string{}
	}
	if state.AutoRoles == nil {
		state.AutoRoles = []protocol.HostRoleSummary{}
	}
	return &state, nil
}

func saveState(path string, state *State) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return errors.New("state file is a symlink or reparse point")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	state.SchemaVersion = stateSchemaVersion
	state.UpdatedAt = time.Now().UTC()
	if state.Roles == nil {
		state.Roles = []string{}
	}
	if state.AutoRoles == nil {
		state.AutoRoles = []protocol.HostRoleSummary{}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
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
	return os.Rename(f.Name(), path)
}
