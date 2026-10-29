package eventlog

import (
	"encoding/json"
	"sort"
	"time"
)

// ChannelEvents is one channel's snapshot. schema_version lets analysis
// tooling detect format changes. Events are chronologically ordered.
type ChannelEvents struct {
	SchemaVersion int        `json:"schema_version"`
	Channel       string     `json:"channel"`
	CapturedAt    time.Time  `json:"captured_at"`
	Since         *time.Time `json:"since,omitempty"` // job.Since, when filtering was requested
	EventCount    int        `json:"event_count"`
	Events        []Event    `json:"events"`
}

// Event carries the System fields analysis relies on plus the named
// EventData fields. Unnamed Data elements are dropped: without a name they
// are not searchable and bloat the artifact.
type Event struct {
	TimeCreated string      `json:"time_created,omitempty"` // TimeCreated/@SystemTime
	RecordID    uint64      `json:"record_id,omitempty"`
	Provider    string      `json:"provider,omitempty"` // Provider/@Name
	Computer    string      `json:"computer,omitempty"`
	EventID     int64       `json:"event_id,omitempty"`
	Level       int         `json:"level,omitempty"`
	Data        []DataField `json:"event_data,omitempty"`
}

// DataField is one named EventData value.
type DataField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Render serializes a snapshot as deterministic JSON: events sorted by
// capture time then record ID, EventData sorted by name, so two renders of
// the same events produce identical bytes.
func Render(c *ChannelEvents) []byte {
	sort.SliceStable(c.Events, func(i, j int) bool {
		a, b := c.Events[i], c.Events[j]
		if a.TimeCreated != b.TimeCreated {
			return a.TimeCreated < b.TimeCreated
		}
		if a.RecordID != b.RecordID {
			return a.RecordID < b.RecordID
		}
		return a.EventID < b.EventID
	})
	for _, e := range c.Events {
		sort.SliceStable(e.Data, func(i, j int) bool { return e.Data[i].Name < e.Data[j].Name })
	}
	c.EventCount = len(c.Events)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		// These types cannot fail to marshal; keep the failure loud anyway.
		return []byte(`{"error":"render failed"}`)
	}
	return data
}
