package main

// Memory analysis wiring: the worker that runs Volatility 3 over a finished
// memory.v1 image and stores the results as derived artifacts.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/dfir-collector/internal/protocol"
	"example.com/dfir-collector/internal/volatility"
)

// volatilityImageArtifact returns the memory image of a job, or nil.
func volatilityImageArtifact(job *protocol.Job) *protocol.Artifact {
	for i := len(job.Artifacts) - 1; i >= 0; i-- {
		if job.Artifacts[i].Kind == protocol.KindMemoryImage {
			return &job.Artifacts[i]
		}
	}
	return nil
}

// volatilityEligible reports whether a job has a finished memory image that
// can be analyzed.
func volatilityEligible(job *protocol.Job) bool {
	return job.Scenario == protocol.ScenarioMemory &&
		(job.Status == "completed" || job.Status == "partial") &&
		volatilityImageArtifact(job) != nil
}

// volatilityTriggerLocked marks a job as analyzing and starts the worker.
// Callers must hold s.mu. force allows a manual re-run of the same image.
func (s *server) volatilityTriggerLocked(job *protocol.Job, force bool) bool {
	if s.volRunner == nil {
		return false
	}
	if !force && !s.volAuto {
		return false
	}
	if !volatilityEligible(job) || job.VolatilityStatus == volatility.StatusRunning {
		return false
	}
	image := volatilityImageArtifact(job)
	if image == nil {
		return false
	}
	if !force && job.VolatilityImage == image.ID && job.VolatilityStatus != "" {
		return false
	}
	previousStatus, previousReason, previousImage := job.VolatilityStatus, job.VolatilityReason, job.VolatilityImage
	job.VolatilityStatus = volatility.StatusRunning
	job.VolatilityReason = ""
	job.VolatilityImage = image.ID
	if err := s.save(job); err != nil {
		job.VolatilityStatus, job.VolatilityReason, job.VolatilityImage = previousStatus, previousReason, previousImage
		log.Printf("volatility trigger: save: %v", err)
		return false
	}
	s.audit("volatility_start", job.ID, "")
	go s.runVolatility(job.ID)
	return true
}

// runVolatility performs one analysis outside the server lock, imports the
// plugin outputs and the report, and records the outcome atomically.
func (s *server) runVolatility(jobID string) {
	// Volatility is memory-hungry and already parallel; one run at a time.
	s.volRunMu.Lock()
	defer s.volRunMu.Unlock()

	s.mu.Lock()
	job := s.jobs[jobID]
	if job == nil || job.VolatilityStatus != volatility.StatusRunning {
		s.mu.Unlock()
		return
	}
	imageArtifact := volatilityImageArtifact(job)
	hostID := job.HostID
	var image protocol.Artifact
	if imageArtifact != nil {
		image = *imageArtifact
	}
	s.mu.Unlock()
	if imageArtifact == nil {
		s.volatilityFinish(jobID, volatility.StatusFailed, "memory image artifact is missing", nil)
		return
	}

	imagePath := filepath.Join(s.dir, "artifacts", jobID, image.ID)
	report, outputs, runErr := s.volRunner.Run(context.Background(), volatility.Input{
		JobID:     jobID,
		HostID:    hostID,
		ImagePath: imagePath,
		Image: volatility.ImageRef{
			ArtifactID: image.ID,
			SHA256:     image.SHA256,
			Size:       image.Size,
		},
	})
	if report == nil {
		reason := "analysis failed"
		if runErr != nil {
			reason += ": " + runErr.Error()
		}
		s.volatilityFinish(jobID, volatility.StatusFailed, reason, nil)
		return
	}

	byName := make(map[string]volatility.PluginOutput, len(outputs))
	for _, output := range outputs {
		byName[output.Name] = output
	}
	var artifacts []protocol.Artifact
	for i := range report.Plugins {
		plugin := &report.Plugins[i]
		if plugin.Status != volatility.StatusCompleted {
			continue
		}
		output, ok := byName[plugin.Name]
		if !ok {
			plugin.Status = volatility.StatusFailed
			plugin.Error = "plugin output was not returned by the runner"
			continue
		}
		artifact, err := s.storeVolatilityArtifact(jobID, protocol.KindVolatilityPlugin,
			plugin.Name+".jsonl",
			"Volatility 3 plugin "+plugin.Name+" output (JSONL, server-generated)",
			output.Data)
		if err != nil {
			plugin.Status = volatility.StatusFailed
			plugin.Error = "store output: " + err.Error()
			continue
		}
		plugin.ArtifactID = artifact.ID
		artifacts = append(artifacts, *artifact)
	}
	// A failed artifact store flips a plugin to failed; recompute the summary
	// so the stored report and the job reason agree with the manifest.
	report.Summary = volatility.Summarize(report.Plugins)

	reportArtifact, err := s.storeVolatilityArtifact(jobID, protocol.KindVolatilityReport,
		"volatility_report.json",
		"Volatility 3 memory analysis summary (server-generated)",
		volatility.Render(report))
	if err != nil {
		s.volatilityFinish(jobID, volatility.StatusFailed, "store analysis report: "+err.Error(), nil)
		return
	}
	artifacts = append(artifacts, *reportArtifact)

	status, reason := volatilityOutcome(report, runErr)
	s.volatilityFinish(jobID, status, reason, artifacts)
}

// volatilityOutcome folds the runner result into a job status and reason.
func volatilityOutcome(report *volatility.Report, runErr error) (string, string) {
	summary := report.Summary
	if runErr != nil {
		return volatility.StatusFailed, runErr.Error()
	}
	if summary.Completed == 0 {
		return volatility.StatusFailed,
			"no plugin completed; the image may not contain a usable Windows kernel layer (capture with winpmem-physical / -1)"
	}
	if summary.Failed > 0 {
		var failed []string
		for _, plugin := range report.Plugins {
			if plugin.Status != volatility.StatusCompleted && len(failed) < 3 {
				failed = append(failed, plugin.Name)
			}
		}
		reason := fmt.Sprintf("%d/%d plugins completed, %d rows", summary.Completed, summary.Requested, summary.Rows)
		if len(failed) > 0 {
			reason += "; failed: " + strings.Join(failed, ", ")
		}
		return volatility.StatusPartial, reason
	}
	return volatility.StatusCompleted,
		fmt.Sprintf("%d/%d plugins completed, %d rows", summary.Completed, summary.Requested, summary.Rows)
}

// storeVolatilityArtifact writes one server-generated file next to the agent
// artifacts. The ID is content-addressed, so an identical re-run is
// idempotent.
func (s *server) storeVolatilityArtifact(jobID string, kind protocol.Kind, source, reason string, data []byte) (*protocol.Artifact, error) {
	hash := sha256.Sum256(data)
	id := sha256.Sum256([]byte(string(kind) + "\x00" + source + "\x00" + hex.EncodeToString(hash[:])))
	now := time.Now().UTC()
	artifact := protocol.Artifact{
		ID:          hex.EncodeToString(id[:]),
		Kind:        kind,
		Source:      source,
		Reason:      reason,
		SHA256:      hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		Mode:        "synthesized",
		ModifiedAt:  now,
		CollectedAt: now,
	}
	dir := filepath.Join(s.dir, "artifacts", jobID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, ".vol-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
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
	name := filepath.Join(dir, artifact.ID)
	if err := os.Rename(f.Name(), name); err != nil {
		return nil, err
	}
	artifact.StoredAt = filepath.ToSlash(filepath.Join("artifacts", jobID, artifact.ID))
	return &artifact, nil
}

// volatilityFinish records the outcome and replaces the previous analysis
// artifacts in the job manifest.
func (s *server) volatilityFinish(jobID, status, reason string, artifacts []protocol.Artifact) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[jobID]
	if job == nil || job.VolatilityStatus != volatility.StatusRunning {
		return
	}
	job.VolatilityStatus = status
	job.VolatilityReason = reason
	if artifacts != nil {
		kept := job.Artifacts[:0]
		for _, artifact := range job.Artifacts {
			if artifact.Kind != protocol.KindVolatilityReport && artifact.Kind != protocol.KindVolatilityPlugin {
				kept = append(kept, artifact)
			}
		}
		job.Artifacts = append(kept, artifacts...)
	}
	if err := s.save(job); err != nil {
		log.Printf("volatility finish: save: %v", err)
	}
	s.audit("volatility", jobID, status+": "+reason)
	log.Printf("job %s: memory analysis %s (%s)", jobID, status, reason)
}

// volatilityTriggerPOST lets the operator re-run analysis from the console.
func (s *server) volatilityTriggerPOST(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	job := s.jobs[r.PathValue("id")]
	if job == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if job.Scenario != protocol.ScenarioMemory {
		s.mu.Unlock()
		http.Error(w, "not a memory job", http.StatusBadRequest)
		return
	}
	if !volatilityEligible(job) {
		s.mu.Unlock()
		http.Error(w, "job has no completed memory image", http.StatusBadRequest)
		return
	}
	if s.volRunner == nil {
		s.mu.Unlock()
		http.Error(w, "memory analysis is not configured on this server", http.StatusBadRequest)
		return
	}
	if job.VolatilityStatus == volatility.StatusRunning {
		s.mu.Unlock()
		http.Error(w, "analysis already running", http.StatusConflict)
		return
	}
	if !s.volatilityTriggerLocked(job, true) {
		s.mu.Unlock()
		http.Error(w, "could not start analysis", http.StatusConflict)
		return
	}
	snapshot := *job
	s.mu.Unlock()
	writeJSON(w, http.StatusAccepted, snapshot)
}
