// Package agent implements the collection agent core: outbound polling,
// evidence upload, and job result aggregation. Scenario logic lives in
// internal/collector subpackages registered at startup.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/hostrole"
	"example.com/dfir-collector/internal/protocol"
)

// Agent polls the server for jobs, runs the matching collector, and reports
// the result.
type Agent struct {
	base     string
	host     string
	token    string
	client   *http.Client
	registry *collector.Registry
	interval time.Duration

	statePath         string
	heartbeatInterval time.Duration
	roleInterval      time.Duration
	roleSource        hostrole.Source
	version           string
	now               func() time.Time

	state         *State
	stateLoaded   bool
	contacted     bool
	nextHeartbeat time.Time
}

// Options configures an Agent.
type Options struct {
	ServerURL         string       // e.g. https://dfir-server:8443
	HostID            string       // must match the server's authorized host ID
	Token             string       // DFIR_AGENT_TOKEN
	Client            *http.Client // optional; defaults to a 60s-timeout client
	Registry          *collector.Registry
	Interval          time.Duration // polling interval, default 5s
	StatePath         string        // local role cache; platform default when empty
	HeartbeatInterval time.Duration // inventory heartbeat, default 1m
	RoleInterval      time.Duration // automatic role detection, default 1h
	RoleSource        hostrole.Source
	Version           string
	Now               func() time.Time // injectable clock for tests
}

// New returns an Agent ready to Run.
func New(o Options) *Agent {
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	interval := o.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	heartbeat := o.HeartbeatInterval
	if heartbeat <= 0 {
		heartbeat = time.Minute
	}
	roleInterval := o.RoleInterval
	if roleInterval <= 0 {
		roleInterval = time.Hour
	}
	statePath := o.StatePath
	if statePath == "" {
		statePath = DefaultStatePath()
	}
	roleSource := o.RoleSource
	if roleSource == nil {
		roleSource = hostrole.NewSource()
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Agent{
		base:              strings.TrimRight(o.ServerURL, "/"),
		host:              o.HostID,
		token:             o.Token,
		client:            client,
		registry:          o.Registry,
		interval:          interval,
		statePath:         statePath,
		heartbeatInterval: heartbeat,
		roleInterval:      roleInterval,
		roleSource:        roleSource,
		version:           o.Version,
		now:               now,
	}
}

// Run polls until ctx is done. Transient errors are logged, not fatal: the
// agent keeps polling and running jobs are retried after a restart.
func (a *Agent) Run(ctx context.Context) {
	// Inventory maintenance is independent of job collection: a long
	// webshell scan must not delay the heartbeat or hold back a manual role
	// assignment.
	go a.inventoryLoop(ctx)
	for {
		if err := a.poll(ctx); err != nil {
			log.Printf("poll/collect: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(a.interval):
		}
	}
}

func (a *Agent) inventoryLoop(ctx context.Context) {
	a.loadInventoryState()
	check := a.heartbeatInterval
	if a.interval < check {
		check = a.interval
	}
	ticker := time.NewTicker(check)
	defer ticker.Stop()
	for {
		a.maintainHost(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *Agent) request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("X-Host-ID", a.host)
	return a.client.Do(req)
}

func (a *Agent) poll(ctx context.Context) error {
	r, err := a.request(ctx, "GET", "/v1/agent/jobs/next", nil)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode == 204 {
		return nil
	}
	if r.StatusCode != 200 {
		return fmt.Errorf("poll: HTTP %d", r.StatusCode)
	}
	var job protocol.Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		return err
	}
	if job.HostID != a.host {
		return errors.New("unexpected host or scenario")
	}
	result, err := a.runJob(ctx, job)
	if err != nil {
		return err // leave the running job available for retry
	}
	b, _ := json.Marshal(result)
	response, err := a.request(ctx, "POST", "/v1/agent/jobs/"+job.ID+"/result", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("finish: HTTP %d", response.StatusCode)
	}
	log.Printf("job %s: %s (%s)", job.ID, result.Status, result.Reason)
	return nil
}

// runJob dispatches a job to its collector and maps sentinel outcomes to
// result statuses. A non-sentinel error is a transport failure: the job
// stays running and is retried on a later poll.
func (a *Agent) runJob(ctx context.Context, job protocol.Job) (protocol.Result, error) {
	c, ok := a.registry.Lookup(job.Scenario)
	if !ok {
		return protocol.Result{Status: "skipped", Reason: "scenario not supported by this agent: " + job.Scenario}, nil
	}
	if !collector.Supports(c, runtime.GOOS) {
		return protocol.Result{
			Status: "skipped",
			Reason: fmt.Sprintf("scenario %s is not implemented on %s", job.Scenario, runtime.GOOS),
		}, nil
	}
	s := newSink(a, ctx, job.ID)
	err := c.Collect(ctx, &job, s)
	if err != nil {
		if errors.Is(err, collector.ErrNotApplicable) {
			return protocol.Result{Status: "skipped", Reason: err.Error()}, nil
		}
		if errors.Is(err, collector.ErrNeedsConfig) {
			return protocol.Result{Status: "needs_configuration", Reason: err.Error()}, nil
		}
		return protocol.Result{}, err
	}
	return s.result(), nil
}
