// Package sinktest provides a Sink implementation for collector tests: it
// records calls instead of uploading, so tests assert what a collector
// decided to collect without any network.
package sinktest

import (
	"fmt"

	"example.com/dfir-collector/internal/protocol"
)

// FileCall records one Sink.File call.
type FileCall struct {
	Kind   protocol.Kind
	Path   string
	Reason string
}

// BytesCall records one Sink.Bytes call.
type BytesCall struct {
	Kind   protocol.Kind
	Name   string
	Reason string
	Data   []byte
}

// Recorded is a collector.Sink that records every call.
type Recorded struct {
	Files      []FileCall
	BytesCalls []BytesCall
	Problems   []string
	Notes      []string
}

func (r *Recorded) File(kind protocol.Kind, path, reason string) error {
	r.Files = append(r.Files, FileCall{Kind: kind, Path: path, Reason: reason})
	return nil
}

func (r *Recorded) Bytes(kind protocol.Kind, name, reason string, data []byte) error {
	r.BytesCalls = append(r.BytesCalls, BytesCall{Kind: kind, Name: name, Reason: reason, Data: data})
	return nil
}

func (r *Recorded) Problem(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

func (r *Recorded) Note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}
