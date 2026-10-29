package agent

import (
	"context"
	"fmt"
	"strings"

	"example.com/dfir-collector/internal/protocol"
)

// sink is the agent's collector.Sink implementation. It uploads evidence,
// counts outcomes, and folds the records into a final protocol.Result with
// the status semantics of the original webshell collection code:
//
//	completed            no failures
//	partial              failures, but at least one artifact collected
//	failed               failures and nothing collected
type sink struct {
	a        *Agent
	ctx      context.Context
	jobID    string
	count    int
	failures int
	problems []string
}

func newSink(a *Agent, ctx context.Context, jobID string) *sink {
	return &sink{a: a, ctx: ctx, jobID: jobID}
}

// Problem records a collection failure.
func (s *sink) Problem(format string, args ...any) {
	s.problem(fmt.Sprintf(format, args...))
}

// Note records an informational detail that never affects the status.
func (s *sink) Note(format string, args ...any) {
	s.problems = appendProblem(s.problems, fmt.Sprintf(format, args...))
}

func (s *sink) problem(p string) {
	s.failures++
	s.problems = appendProblem(s.problems, p)
}

// result folds the records into the final job result.
func (s *sink) result() protocol.Result {
	status := "completed"
	if s.failures > 0 {
		status = "partial"
		if s.count == 0 {
			status = "failed"
		}
	}
	reason := fmt.Sprintf("collected %d artifacts, %d errors", s.count, s.failures)
	if len(s.problems) > 0 {
		reason += "; " + strings.Join(s.problems, "; ")
	}
	return protocol.Result{Status: status, Reason: reason}
}

// appendProblem keeps the reason readable: at most five recorded details.
func appendProblem(xs []string, p string) []string {
	if len(xs) < 5 {
		return append(xs, p)
	}
	return xs
}
