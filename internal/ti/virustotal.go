package ti

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by Lookup. The enrichment engine stops early on
// both: a rejected key fails every query, and a 429 means the shared quota
// is exhausted no matter how patiently we wait.
var (
	ErrInvalidKey  = errors.New("VirusTotal rejected the API key (check the key in Threat Intel settings)")
	errRateLimited = errors.New("rate limited by VirusTotal (HTTP 429); wait a minute and re-run")
)

// VTClient queries the VirusTotal v3 API with the shared disk cache and a
// process-wide rate limiter, so concurrent enrichment runs together stay
// inside the configured requests-per-minute budget.
type VTClient struct {
	store *SettingsStore
	cache *Cache
	http  *http.Client

	mu       sync.Mutex // guards nextSlot
	nextSlot time.Time
}

func NewVTClient(store *SettingsStore, cache *Cache) *VTClient {
	return &VTClient{store: store, cache: cache, http: &http.Client{Timeout: 20 * time.Second}}
}

// Enabled reports whether an API key is configured.
func (c *VTClient) Enabled() bool {
	return c.store.Get().VTAPIKey != ""
}

// Stats is the VirusTotal last_analysis_stats object.
type Stats struct {
	Harmless   int `json:"harmless"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Timeout    int `json:"timeout"`
}

// Total is the number of engines that returned a verdict.
func (s Stats) Total() int {
	return s.Harmless + s.Malicious + s.Suspicious + s.Undetected + s.Timeout
}

// Detections renders the "flagged / total" ratio shown in the console.
func (s Stats) Detections() string {
	return fmt.Sprintf("%d/%d", s.Malicious+s.Suspicious, s.Total())
}

// VTResult is the distilled VirusTotal answer for one indicator.
type VTResult struct {
	Stats       Stats     `json:"stats"`
	Reputation  int64     `json:"reputation"`
	ASOwner     string    `json:"as_owner,omitempty"`
	Country     string    `json:"country,omitempty"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

// Lookup returns the VirusTotal verdict for one indicator. kind is "ip" or
// "domain". A fresh cached entry short-circuits both the rate limiter and
// the HTTP call; a 404 (unknown to VirusTotal) yields zero stats, which the
// engine renders as "unrated" rather than an error.
func (c *VTClient) Lookup(ctx context.Context, kind, value string) (res VTResult, fromCache bool, err error) {
	key := kind + ":" + strings.ToLower(value)
	if cached, ok := c.cache.get(key); ok {
		return cached, true, nil
	}
	if err := c.throttle(ctx); err != nil {
		return VTResult{}, false, err
	}

	settings := c.store.Get()
	if settings.VTAPIKey == "" {
		return VTResult{}, false, ErrInvalidKey
	}
	endpoint, err := vtEndpoint(kind, value)
	if err != nil {
		return VTResult{}, false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, settings.BaseURL()+endpoint, nil)
	if err != nil {
		return VTResult{}, false, err
	}
	req.Header.Set("x-apikey", settings.VTAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return VTResult{}, false, fmt.Errorf("VirusTotal request failed: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		// Unknown to VirusTotal: zero stats -> "unrated".
		res := VTResult{RetrievedAt: time.Now().UTC()}
		c.cache.put(key, res)
		return res, false, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return VTResult{}, false, ErrInvalidKey
	case resp.StatusCode == http.StatusTooManyRequests:
		return VTResult{}, false, errRateLimited
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return VTResult{}, false, fmt.Errorf("VirusTotal HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Data struct {
			Attributes struct {
				Reputation int64  `json:"reputation"`
				ASOwner    string `json:"as_owner"`
				Country    string `json:"country"`
				LastStats  Stats  `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return VTResult{}, false, fmt.Errorf("decode VirusTotal response: %w", err)
	}
	res = VTResult{
		Stats:       out.Data.Attributes.LastStats,
		Reputation:  out.Data.Attributes.Reputation,
		ASOwner:     out.Data.Attributes.ASOwner,
		Country:     out.Data.Attributes.Country,
		RetrievedAt: time.Now().UTC(),
	}
	c.cache.put(key, res)
	return res, false, nil
}

// vtEndpoint builds the v3 object path for an IP or domain.
func vtEndpoint(kind, value string) (string, error) {
	switch kind {
	case "ip":
		return "/api/v3/ip_addresses/" + url.PathEscape(value), nil
	case "domain":
		return "/api/v3/domains/" + url.PathEscape(value), nil
	default:
		return "", fmt.Errorf("unknown indicator kind %q", kind)
	}
}

// throttle reserves the next request slot once and sleeps until it, so
// the client never exceeds rate_per_min across all concurrent users.
func (c *VTClient) throttle(ctx context.Context) error {
	delay := c.reserveSlot()
	if delay <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

func (c *VTClient) reserveSlot() time.Duration {
	rate := c.store.Get().VTRatePerMin
	if rate <= 0 {
		rate = DefaultRatePerMin
	}
	interval := time.Minute / time.Duration(rate)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.nextSlot.Before(now) {
		c.nextSlot = now
	}
	delay := c.nextSlot.Sub(now)
	c.nextSlot = c.nextSlot.Add(interval)
	return delay
}

// SaveCache persists the shared verdict cache; called after each run.
func (c *VTClient) SaveCache() error {
	return c.cache.Save()
}
