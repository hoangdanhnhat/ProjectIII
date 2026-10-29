// Package eventlog implements the eventlog.v1 scenario: Windows event log
// channels collected as versioned JSON snapshots. job.Since filters each
// channel to events at or after the requested time (XPath query); omitted,
// the whole channel snapshot covers the newest events first.
//
// # Subprocess policy
//
// This scenario runs the only subprocess in the codebase. The rules, which
// apply to any future scenario that needs a system command:
//
//   - The binary must be a vetted OS component, never something we download
//     or write to disk at runtime. Here that is wevtutil, resolved via
//     PATH from its system location (%SystemRoot%\System32).
//   - Arguments are fixed by the code. Host- or job-derived values enter
//     argv as separate elements via exec.Command, never through a shell, so
//     there is no injection surface: no string concatenation into a command
//     line, no cmd.exe, no "sh -c".
//   - Mutable strings that end up in argv (channel names) are validated by
//     validateChannel: no leading '-' or '/', few non-printing characters.
//   - Every invocation is documented per scenario in this header. The exact
//     commands are: wevtutil qe <channel> /f:xml /rd:true /uni:true
//     and, when the job has a Since bound, an additional /q: argument with
//     an XPath time filter (built in sinceQuery).
package eventlog

import (
	"context"
	"errors"
	"strings"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// Options configures the scenario: which channels to collect.
type Options struct {
	Channels []string
}

// New returns the eventlog.v1 collector.
func New(o Options) collector.Collector {
	return &scenario{channels: o.Channels}
}

type scenario struct {
	channels []string
}

func (s *scenario) ID() string          { return protocol.ScenarioEventlog }
func (s *scenario) Platforms() []string { return []string{"windows"} }

func (s *scenario) Collect(ctx context.Context, job *protocol.Job, sink collector.Sink) error {
	if len(s.channels) == 0 {
		return collector.ErrNeedsConfig
	}
	return s.collectChannels(ctx, job, sink)
}

// SplitChannels parses the configured channel list into non-empty,
// whitespace-trimmed names. Exported because the agent's flag parsing uses
// it too.
func SplitChannels(v string) []string {
	var out []string
	for _, raw := range strings.Split(v, ",") {
		if ch := strings.TrimSpace(raw); ch != "" {
			out = append(out, ch)
		}
	}
	return out
}

// sinceQuery builds the wevtutil /q XPath for the job's Since boundary.
// The timestamp format is the one wevtutil requires in SystemTime
// comparisons: UTC with a trailing Z and exactly three millisecond digits.
func sinceQuery(t time.Time) string {
	return "*[System[TimeCreated[@SystemTime>='" + t.UTC().Format("2006-01-02T15:04:05.000Z") + "']]]"
}

// safeFilename turns a channel name into a safe file stem for the artifact
// name, keeping the rest of the name readable.
func safeFilename(channel string) string {
	var b strings.Builder
	for _, r := range channel {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// validateChannel rejects strings that could be parsed as an option or
// break the subprocess: wevtutil takes options as /name or -name, so a
// channel value starting with one of those characters is ambiguous.
func validateChannel(ch string) error {
	if ch == "" {
		return errors.New("empty channel name")
	}
	if strings.HasPrefix(ch, "-") || strings.HasPrefix(ch, "/") {
		return errors.New("channel names must not start with '-' or '/'")
	}
	for _, r := range ch {
		if r < 0x20 || r == 0x7f {
			return errors.New("channel names must not contain control characters")
		}
	}
	return nil
}
