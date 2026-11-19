package volatility

import (
	"encoding/json"
)

// Summarize aggregates plugin results for the report.
func Summarize(plugins []PluginResult) Summary {
	var summary Summary
	summary.Requested = len(plugins)
	for _, plugin := range plugins {
		summary.Rows += plugin.Rows
		switch plugin.Status {
		case StatusCompleted:
			summary.Completed++
		case statusOversized:
			summary.Failed++
			summary.Oversized++
		default:
			summary.Failed++
		}
	}
	return summary
}

// Render serializes a report as indented JSON. Slices are always emitted as
// arrays so analysis tooling never has to handle null.
func Render(r *Report) []byte {
	if r.Plugins == nil {
		r.Plugins = []PluginResult{}
	}
	if r.Notes == nil {
		r.Notes = []string{}
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		// These types cannot fail to marshal; keep the failure loud anyway.
		return []byte(`{"error":"render failed"}`)
	}
	return data
}
