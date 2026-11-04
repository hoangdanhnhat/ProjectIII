package main

// Threat-intel wiring for the coordination server: the enrichment worker
// that turns a finished netstat.v1 job into a ti_report artifact, and the
// operator endpoints that let the console manage VirusTotal settings, the
// whitelist, and re-runs without any terminal configuration.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/dfir-collector/internal/collector/netstat"
	"example.com/dfir-collector/internal/protocol"
	"example.com/dfir-collector/internal/ti"
)

// maxEnrichmentTime bounds one enrichment run (queries are rate limited,
// so the worst case is the query cap times the request interval).
const maxEnrichmentTime = 30 * time.Minute

// tiReportArtifact returns the latest ti_report artifact of a job, or nil.
func tiReportArtifact(job *protocol.Job) *protocol.Artifact {
	for i := len(job.Artifacts) - 1; i >= 0; i-- {
		if job.Artifacts[i].Kind == protocol.KindTIReport {
			return &job.Artifacts[i]
		}
	}
	return nil
}

// tiSnapshotArtifact returns the netstat snapshot artifact of a job, or nil.
func tiSnapshotArtifact(job *protocol.Job) *protocol.Artifact {
	for i := range job.Artifacts {
		if job.Artifacts[i].Kind == protocol.KindNetstatSnapshot {
			return &job.Artifacts[i]
		}
	}
	return nil
}

// tiEligible reports whether a finished job can be enriched: it must be a
// netstat.v1 job that completed (possibly partial) with a snapshot on disk.
func tiEligible(job *protocol.Job) bool {
	return job.Scenario == protocol.ScenarioNetstat &&
		(job.Status == "completed" || job.Status == "partial") &&
		tiSnapshotArtifact(job) != nil
}

// tiTriggerLocked marks the job as being enriched and starts the worker.
// Callers must hold s.mu. Returns false (job untouched) when the job cannot
// be enriched or a run is already active.
func (s *server) tiTriggerLocked(job *protocol.Job) bool {
	if !tiEligible(job) || job.TIStatus == ti.StatusRunning {
		return false
	}
	previous := job.TIStatus
	job.TIStatus = ti.StatusRunning
	job.TIReason = ""
	if err := s.save(job); err != nil {
		job.TIStatus = previous
		log.Printf("ti trigger: save: %v", err)
		return false
	}
	s.audit("ti_start", job.ID, "")
	go s.runTIEnrichment(job.ID)
	return true
}

// runTIEnrichment performs the enrichment outside the server lock so a
// slow, rate-limited VirusTotal run never blocks the API, then records the
// result atomically.
func (s *server) runTIEnrichment(jobID string) {
	s.mu.Lock()
	job := s.jobs[jobID]
	if job == nil || job.TIStatus != ti.StatusRunning {
		s.mu.Unlock()
		return
	}
	snapshot := tiSnapshotArtifact(job)
	hostID := job.HostID
	s.mu.Unlock()
	if snapshot == nil {
		s.tiFinish(jobID, ti.StatusFailed, "netstat snapshot artifact missing", nil)
		return
	}

	data, err := os.ReadFile(filepath.Join(s.dir, "artifacts", jobID, snapshot.ID))
	if err != nil {
		s.tiFinish(jobID, ti.StatusFailed, "read snapshot: "+err.Error(), nil)
		return
	}
	snap, err := netstat.Parse(data)
	if err != nil {
		s.tiFinish(jobID, ti.StatusFailed, "parse snapshot: "+err.Error(), nil)
		return
	}

	engine := &ti.Engine{Store: s.settings, Whitelist: s.whitelist, Blacklist: s.blacklist, VT: s.vt}
	ctx, cancel := context.WithTimeout(context.Background(), maxEnrichmentTime)
	defer cancel()
	report, status, reason := engine.Run(ctx, ti.EnrichInput{
		Snapshot:       snap,
		JobID:          jobID,
		HostID:         hostID,
		SourceArtifact: snapshot.ID,
	})

	bytes := ti.RenderReport(report)
	artifact, err := s.storeTIReport(jobID, bytes, report)
	if err != nil {
		log.Printf("ti report store: %v", err)
		s.tiFinish(jobID, ti.StatusFailed, "store report: "+err.Error(), nil)
		return
	}
	s.tiFinish(jobID, status, reason, artifact)
}

// storeTIReport writes the report bytes next to the agent artifacts and
// returns its metadata. The ID is derived from the content like agent
// uploads, so a re-run with identical content is idempotent.
func (s *server) storeTIReport(jobID string, bytes []byte, report *ti.Report) (*protocol.Artifact, error) {
	hash := sha256.Sum256(bytes)
	id := sha256.Sum256([]byte(string(protocol.KindTIReport) + "\x00" + "ti_report.json" + "\x00" + hex.EncodeToString(hash[:])))
	artifact := protocol.Artifact{
		ID:          hex.EncodeToString(id[:]),
		Kind:        protocol.KindTIReport,
		Source:      "ti_report.json",
		Reason:      "VirusTotal enrichment of the netstat snapshot (server-generated)",
		SHA256:      hex.EncodeToString(hash[:]),
		Size:        int64(len(bytes)),
		Mode:        "synthesized",
		ModifiedAt:  time.Now().UTC(),
		CollectedAt: time.Now().UTC(),
	}
	dir := filepath.Join(s.dir, "artifacts", jobID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, artifact.ID)); errors.Is(err, fs.ErrNotExist) {
		f, err := os.CreateTemp(dir, ".upload-*")
		if err != nil {
			return nil, err
		}
		tmp := f.Name()
		defer os.Remove(tmp)
		if _, err := f.Write(bytes); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, filepath.Join(dir, artifact.ID)); err != nil {
			return nil, err
		}
	}
	artifact.StoredAt = filepath.ToSlash(filepath.Join("artifacts", jobID, artifact.ID))
	return &artifact, nil
}

// tiFinish records the enrichment outcome. A re-run supersedes the previous
// ti_report reference in the manifest; superseded files stay on disk as
// evidence (chain of custody beats list cleanliness).
func (s *server) tiFinish(jobID, status, reason string, artifact *protocol.Artifact) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[jobID]
	if job == nil || job.TIStatus != ti.StatusRunning {
		return
	}
	job.TIStatus = status
	job.TIReason = reason
	if artifact != nil {
		kept := job.Artifacts[:0]
		for _, a := range job.Artifacts {
			if a.Kind != protocol.KindTIReport {
				kept = append(kept, a)
			}
		}
		job.Artifacts = append(kept, *artifact)
	}
	if err := s.save(job); err != nil {
		log.Printf("ti finish: save: %v", err)
	}
	s.audit("ti", jobID, status+": "+reason)
}

/* -------------------------------------------------------------------------
   Operator endpoints
   ------------------------------------------------------------------------- */

// tiSettingsGET reports the current TI configuration. The API key is
// masked: the console shows whether a key is configured, never the key.
func (s *server) tiSettingsGET(w http.ResponseWriter, r *http.Request) {
	st := s.settings.Get()
	preview := ""
	if st.VTAPIKey != "" {
		if len(st.VTAPIKey) > 4 {
			preview = "••••" + st.VTAPIKey[len(st.VTAPIKey)-4:]
		} else {
			preview = "••••"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vt": map[string]any{
			"configured":          st.VTAPIKey != "",
			"key_preview":         preview,
			"auto_enrich":         st.VTAutoEnrich,
			"rate_per_min":        st.VTRatePerMin,
			"max_queries_per_job": st.VTMaxQueries,
		},
		"whitelist": map[string]any{"entries": s.whitelist.List()},
		"blacklist": map[string]any{"entries": s.blacklist.List()},
	})
}

// tiSettingsPUT updates the VirusTotal settings from the console.
func (s *server) tiSettingsPUT(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VTAPIKey     *string `json:"vt_api_key"` // nil = unchanged; "" = clear
		VTAutoEnrich *bool   `json:"vt_auto_enrich"`
		VTRatePerMin *int    `json:"vt_rate_per_min"`
		VTMaxQueries *int    `json:"vt_max_queries_per_job"`
		VTBaseURL    *string `json:"vt_base_url"` // advanced/testing only
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if req.VTRatePerMin != nil && (*req.VTRatePerMin < 1 || *req.VTRatePerMin > 60) {
		http.Error(w, "rate_per_min must be between 1 and 60", 400)
		return
	}
	if req.VTMaxQueries != nil && (*req.VTMaxQueries < 1 || *req.VTMaxQueries > 500) {
		http.Error(w, "max_queries_per_job must be between 1 and 500", 400)
		return
	}
	if req.VTBaseURL != nil && *req.VTBaseURL != "" &&
		!strings.HasPrefix(*req.VTBaseURL, "http://") && !strings.HasPrefix(*req.VTBaseURL, "https://") {
		http.Error(w, "base URL must start with http:// or https://", 400)
		return
	}
	err := s.settings.Update(func(st *ti.Settings) {
		if req.VTAPIKey != nil {
			st.VTAPIKey = strings.TrimSpace(*req.VTAPIKey)
		}
		if req.VTAutoEnrich != nil {
			st.VTAutoEnrich = *req.VTAutoEnrich
		}
		if req.VTRatePerMin != nil {
			st.VTRatePerMin = *req.VTRatePerMin
		}
		if req.VTMaxQueries != nil {
			st.VTMaxQueries = *req.VTMaxQueries
		}
		if req.VTBaseURL != nil {
			st.VTBaseURL = strings.TrimSpace(*req.VTBaseURL)
		}
	})
	if err != nil {
		http.Error(w, "storage failure", 500)
		return
	}
	s.audit("settings", "", "ti settings updated")
	s.tiSettingsGET(w, r)
}

// listPOST adds or updates an entry (IP, CIDR, domain or wildcard domain)
// with an optional note in the named list ("whitelist" or "blacklist").
func (s *server) listPOST(store *ti.ListStore, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Value string `json:"value"`
			Note  string `json:"note"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if len(req.Note) > 200 {
			http.Error(w, "note too long (200 chars max)", 400)
			return
		}
		existed := false
		for _, e := range store.List() {
			if e.Value == strings.TrimSpace(req.Value) {
				existed = true
				break
			}
		}
		entry, err := store.Add(req.Value, req.Note)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		status := http.StatusCreated
		if existed {
			status = http.StatusOK
		}
		s.audit(name+"_add", entry.ID, entry.Type+" "+entry.Value)
		writeJSON(w, status, entry)
	}
}

// listDELETE removes one entry by ID from the named list.
func (s *server) listDELETE(store *ti.ListStore, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !store.Remove(id) {
			http.NotFound(w, r)
			return
		}
		s.audit(name+"_remove", id, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

// tiTriggerPOST re-runs enrichment for one job on operator demand (after
// adding a VirusTotal key or updating the whitelist).
func (s *server) tiTriggerPOST(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	job := s.jobs[r.PathValue("id")]
	if job == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if job.Scenario != protocol.ScenarioNetstat {
		s.mu.Unlock()
		http.Error(w, "threat intel applies to netstat.v1 collections", 400)
		return
	}
	if job.Status != "completed" && job.Status != "partial" {
		s.mu.Unlock()
		http.Error(w, "job has not finished yet", 409)
		return
	}
	if job.TIStatus == ti.StatusRunning {
		s.mu.Unlock()
		http.Error(w, "enrichment already running", 409)
		return
	}
	if tiSnapshotArtifact(job) == nil {
		s.mu.Unlock()
		http.Error(w, "job has no netstat snapshot artifact", 409)
		return
	}
	if !s.tiTriggerLocked(job) {
		s.mu.Unlock()
		http.Error(w, "could not start enrichment", 500)
		return
	}
	// Respond under the lock: the worker goroutine is parked on s.mu and
	// tiFinish rewrites the artifact slice in place once it acquires it.
	writeJSON(w, http.StatusAccepted, job)
	s.mu.Unlock()
}
