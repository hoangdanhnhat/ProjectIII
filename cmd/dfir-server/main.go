package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"example.com/dfir-collector/internal/protocol"
	"example.com/dfir-collector/internal/ti"
	"example.com/dfir-collector/internal/webui"
)

const maxArtifact = 10 << 20

type server struct {
	mu                                     sync.Mutex
	dir, hostID, operatorToken, agentToken string
	jobs                                   map[string]*protocol.Job
	// threat-intel state: operator-managed settings and white/blacklists,
	// shared VirusTotal client with its persistent verdict cache.
	settings  *ti.SettingsStore
	whitelist *ti.ListStore
	blacklist *ti.ListStore
	vt        *ti.VTClient
}

func main() {
	addr := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dir := flag.String("data", "./data", "evidence directory")
	host := flag.String("host-id", "lab-ubuntu", "authorized agent host ID")
	cert := flag.String("tls-cert", "", "optional TLS certificate (enables HTTPS)")
	key := flag.String("tls-key", "", "optional TLS private key")
	flag.Parse()
	op := os.Getenv("DFIR_OPERATOR_TOKEN")
	ag := os.Getenv("DFIR_AGENT_TOKEN")
	if op == "" || ag == "" || op == ag {
		log.Fatal("set distinct DFIR_OPERATOR_TOKEN and DFIR_AGENT_TOKEN")
	}
	if (*cert == "") != (*key == "") {
		log.Fatal("set both TLS certificate and key")
	}
	s, err := newServer(*dir, *host, op, ag)
	if err != nil {
		log.Fatal(err)
	}
	if *cert == "" {
		// Plain HTTP is the lab default. Bearer tokens travel in clear text,
		// so this is acceptable only on a trusted lab network.
		log.Printf("warning: serving plain HTTP without TLS; use only on a trusted lab network")
	}
	log.Printf("DFIR server listening at %s for host %s", *addr, *host)
	httpServer := &http.Server{Addr: *addr, Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second}
	if *cert != "" {
		err = httpServer.ListenAndServeTLS(*cert, *key)
	} else {
		err = httpServer.ListenAndServe()
	}
	log.Fatal(err)
}

func newServer(dir, host, op, ag string) (*server, error) {
	if host == "" || strings.ContainsAny(host, "/\\") {
		return nil, errors.New("invalid host ID")
	}
	for _, d := range []string{dir, filepath.Join(dir, "jobs"), filepath.Join(dir, "artifacts")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, err
		}
	}
	s := &server{dir: dir, hostID: host, operatorToken: op, agentToken: ag, jobs: make(map[string]*protocol.Job)}
	settings, err := ti.LoadSettings(dir)
	if err != nil {
		return nil, err
	}
	whitelist, err := ti.LoadWhitelist(dir)
	if err != nil {
		return nil, err
	}
	blacklist, err := ti.LoadBlacklist(dir)
	if err != nil {
		return nil, err
	}
	s.settings = settings
	s.whitelist = whitelist
	s.blacklist = blacklist
	s.vt = ti.NewVTClient(settings, ti.LoadCache(dir))
	files, err := filepath.Glob(filepath.Join(dir, "jobs", "*.json"))
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var job protocol.Job
		if err := json.Unmarshal(b, &job); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if job.ID == "" || filepath.Base(file) != job.ID+".json" {
			return nil, fmt.Errorf("invalid job file %s", file)
		}
		// An enrichment run that was in flight when the server stopped
		// cannot be resumed (the worker was in memory); surface that
		// honestly instead of leaving a stuck "running" status.
		if job.TIStatus == ti.StatusRunning {
			job.TIStatus = ti.StatusInterrupted
			job.TIReason = "enrichment interrupted by server restart; re-run it from the console"
			if err := s.save(&job); err != nil {
				return nil, err
			}
		}
		s.jobs[job.ID] = &job
	}
	return s, nil
}

func (s *server) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/jobs", s.auth(false, s.create))
	m.HandleFunc("GET /v1/jobs", s.auth(false, s.list))
	m.HandleFunc("GET /v1/jobs/{id}", s.auth(false, s.get))
	m.HandleFunc("GET /v1/jobs/{id}/artifacts/{artifact}", s.auth(false, s.download))
	m.HandleFunc("GET /v1/meta", s.auth(false, s.meta))
	m.HandleFunc("GET /v1/settings/ti", s.auth(false, s.tiSettingsGET))
	m.HandleFunc("PUT /v1/settings/ti", s.auth(false, s.tiSettingsPUT))
	m.HandleFunc("POST /v1/whitelist", s.auth(false, s.listPOST(s.whitelist, "whitelist")))
	m.HandleFunc("DELETE /v1/whitelist/{id}", s.auth(false, s.listDELETE(s.whitelist, "whitelist")))
	m.HandleFunc("POST /v1/blacklist", s.auth(false, s.listPOST(s.blacklist, "blacklist")))
	m.HandleFunc("DELETE /v1/blacklist/{id}", s.auth(false, s.listDELETE(s.blacklist, "blacklist")))
	m.HandleFunc("POST /v1/jobs/{id}/ti", s.auth(false, s.tiTriggerPOST))
	m.HandleFunc("GET /v1/agent/jobs/next", s.auth(true, s.next))
	m.HandleFunc("POST /v1/agent/jobs/{id}/artifacts/{artifact}", s.auth(true, s.upload))
	m.HandleFunc("POST /v1/agent/jobs/{id}/result", s.auth(true, s.result))
	m.Handle("GET /", webui.Handler())
	return m
}

func (s *server) auth(agent bool, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		want := s.operatorToken
		if agent {
			want = s.agentToken
			if r.Header.Get("X-Host-ID") != s.hostID {
				http.Error(w, "unauthorized host", 403)
				return
			}
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		fn(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *server) save(job *protocol.Job) error {
	b, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Join(s.dir, "jobs"), ".job-*")
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
	return os.Rename(f.Name(), filepath.Join(s.dir, "jobs", job.ID+".json"))
}

func (s *server) audit(event, jobID, detail string) {
	f, err := os.OpenFile(filepath.Join(s.dir, "audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("audit open: %v", err)
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(map[string]string{"at": time.Now().UTC().Format(time.RFC3339Nano), "event": event, "job_id": jobID, "detail": detail})
}

func (s *server) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HostID   string     `json:"host_id"`
		Scenario string     `json:"scenario"`
		Since    *time.Time `json:"since"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if req.HostID != s.hostID {
		http.Error(w, "unsupported host", 400)
		return
	}
	if _, ok := protocol.ScenarioByID(req.Scenario); !ok {
		http.Error(w, "unsupported scenario", 400)
		return
	}
	if req.Since != nil && req.Since.After(time.Now()) {
		http.Error(w, "since must not be in future", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job := &protocol.Job{ID: newID(), HostID: req.HostID, Scenario: req.Scenario, Since: req.Since, Status: "queued", CreatedAt: time.Now().UTC(), Artifacts: []protocol.Artifact{}}
	if err := s.save(job); err != nil {
		http.Error(w, "storage failure", 500)
		return
	}
	s.jobs[job.ID] = job
	s.audit("create", job.ID, req.Scenario)
	writeJSON(w, 201, job)
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[r.PathValue("id")]
	if job == nil {
		http.NotFound(w, r)
		return
	}
	s.audit("view", job.ID, "job")
	writeJSON(w, 200, job)
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs := make([]*protocol.Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	slices.SortFunc(jobs, func(a, b *protocol.Job) int {
		return b.CreatedAt.Compare(a.CreatedAt)
	})
	writeJSON(w, 200, map[string]any{"jobs": jobs})
}

func (s *server) meta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"host_id":   s.hostID,
		"scenarios": protocol.ScenarioIDs(),
	})
}

func (s *server) next(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var selected *protocol.Job
	for _, j := range s.jobs {
		if j.HostID != s.hostID || (j.Status != "queued" && j.Status != "running") {
			continue
		}
		if selected == nil || j.CreatedAt.Before(selected.CreatedAt) {
			selected = j
		}
	}
	if selected == nil {
		w.WriteHeader(204)
		return
	}
	if selected.Status == "queued" {
		now := time.Now().UTC()
		selected.StartedAt = &now
		selected.Status = "running"
		if err := s.save(selected); err != nil {
			http.Error(w, "storage failure", 500)
			return
		}
		s.audit("start", selected.ID, "")
	}
	writeJSON(w, 200, selected)
}

func (s *server) upload(w http.ResponseWriter, r *http.Request) {
	id, aid := r.PathValue("id"), r.PathValue("artifact")
	var a protocol.Artifact
	if err := json.Unmarshal([]byte(r.Header.Get("X-Artifact-Metadata")), &a); err != nil || a.ID != aid || len(aid) != 64 || len(a.SHA256) != 64 || a.Size < 0 || a.Size > maxArtifact || a.Source == "" || a.Kind == "" {
		http.Error(w, "invalid artifact metadata", 400)
		return
	}
	if _, err := hex.DecodeString(aid); err != nil {
		http.Error(w, "invalid artifact ID", 400)
		return
	}
	if _, err := hex.DecodeString(a.SHA256); err != nil {
		http.Error(w, "invalid hash", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[id]
	if job == nil || job.Status != "running" {
		http.Error(w, "job not running", 409)
		return
	}
	scenario, ok := protocol.ScenarioByID(job.Scenario)
	if !ok || !scenario.AcceptsKind(a.Kind) {
		http.Error(w, "invalid artifact metadata", 400)
		return
	}
	for _, existing := range job.Artifacts {
		if existing.ID == aid {
			if existing.SHA256 == a.SHA256 && existing.Source == a.Source && existing.Kind == a.Kind {
				w.WriteHeader(200)
			} else {
				http.Error(w, "artifact ID conflict", 409)
			}
			return
		}
	}
	if len(job.Artifacts) >= 260 {
		http.Error(w, "artifact count limit reached", 413)
		return
	}
	dir := filepath.Join(s.dir, "artifacts", id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		http.Error(w, "storage failure", 500)
		return
	}
	f, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		http.Error(w, "storage failure", 500)
		return
	}
	defer os.Remove(f.Name())
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), http.MaxBytesReader(w, r.Body, maxArtifact+1))
	if err != nil || n != a.Size || hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		f.Close()
		http.Error(w, "size or SHA-256 mismatch", 400)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		http.Error(w, "storage failure", 500)
		return
	}
	if err := f.Close(); err != nil {
		http.Error(w, "storage failure", 500)
		return
	}
	name := filepath.Join(dir, aid)
	if err := os.Rename(f.Name(), name); err != nil {
		http.Error(w, "storage failure", 500)
		return
	}
	a.StoredAt = filepath.ToSlash(filepath.Join("artifacts", id, aid))
	job.Artifacts = append(job.Artifacts, a)
	if err := s.save(job); err != nil {
		job.Artifacts = job.Artifacts[:len(job.Artifacts)-1]
		http.Error(w, "storage failure", 500)
		return
	}
	s.audit("artifact", id, aid)
	w.WriteHeader(201)
}

func (s *server) result(w http.ResponseWriter, r *http.Request) {
	var res protocol.Result
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&res); err != nil {
		http.Error(w, "invalid result", 400)
		return
	}
	if res.Status != "completed" && res.Status != "partial" && res.Status != "failed" && res.Status != "skipped" && res.Status != "needs_configuration" {
		http.Error(w, "invalid status", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[r.PathValue("id")]
	if job == nil {
		http.NotFound(w, r)
		return
	}
	if job.Status != "running" {
		http.Error(w, "job not running", 409)
		return
	}
	copy := *job
	now := time.Now().UTC()
	copy.EndedAt = &now
	copy.Status = res.Status
	copy.Reason = res.Reason
	if err := s.save(&copy); err != nil {
		http.Error(w, "storage failure", 500)
		return
	}
	*job = copy
	s.audit("finish", job.ID, res.Status+": "+res.Reason)
	// Completed netstat.v1 jobs are enriched automatically (when enabled)
	// so the console shows VirusTotal verdicts without operator action.
	if s.settings.Get().VTAutoEnrich {
		s.tiTriggerLocked(job)
	}
	writeJSON(w, 200, job)
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[r.PathValue("id")]
	if job == nil {
		http.NotFound(w, r)
		return
	}
	for _, a := range job.Artifacts {
		if a.ID == r.PathValue("artifact") {
			name := filepath.Join(s.dir, "artifacts", job.ID, a.ID)
			data, err := os.ReadFile(name)
			if err != nil {
				http.Error(w, "artifact missing", 500)
				return
			}
			hash := sha256.Sum256(data)
			if int64(len(data)) != a.Size || hex.EncodeToString(hash[:]) != a.SHA256 {
				http.Error(w, "stored artifact failed integrity check", 500)
				return
			}
			s.audit("download", job.ID, a.ID)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("X-SHA256", a.SHA256)
			_, _ = w.Write(data)
			return
		}
	}
	http.NotFound(w, r)
}
