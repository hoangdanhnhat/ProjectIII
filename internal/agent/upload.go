package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// maxArtifact matches the server's default per-artifact size limit for every
// kind except memory_image.
const maxArtifact = 10 << 20

// DefaultMemoryImageLimit is the agent-side cap for one memory_image artifact.
// Keep it aligned with the server's -max-memory-image flag; the server remains
// authoritative, this only avoids uploading an image the server will reject.
const DefaultMemoryImageLimit int64 = 16 << 30 // 16 GiB

// Upload deadlines: small artifacts get a minute, large ones get additional
// time at an assumed minimum throughput. The general HTTP client keeps its
// short timeout for polling and heartbeats; uploads use uploadClient and the
// per-request deadline below.
const (
	uploadFloorTimeout = 60 * time.Second
	uploadMinRate      = 512 << 10 // bytes per second
	uploadMaxTimeout   = 4 * time.Hour
)

// networkError marks transport failures. The sink returns them so collectors
// abort and the job stays running for a retry, instead of recording every
// remaining file as a failure.
type networkError struct{ error }

// rejectError marks an artifact the server refused outright (invalid metadata
// or size, or the job's artifact budget). Retrying the same artifact would
// fail identically, so the sink records it as a problem instead of a
// transport error.
type rejectError struct{ error }

// artifactLimit returns the size cap for one artifact kind.
func (a *Agent) artifactLimit(kind protocol.Kind) int64 {
	if kind == protocol.KindMemoryImage {
		return a.memoryImageLimit
	}
	return maxArtifact
}

// uploadTimeout sizes the deadline for one upload from the byte count.
func uploadTimeout(size int64) time.Duration {
	d := uploadFloorTimeout
	if size > 0 {
		d += time.Duration(size/uploadMinRate) * time.Second
	}
	if d > uploadMaxTimeout {
		return uploadMaxTimeout
	}
	return d
}

// File implements collector.Sink: open without following symlinks, verify the
// file did not change while reading, hash the exact bytes sent, and stream
// them from disk. The body is never buffered in memory, so the same path
// serves a 5 KiB script and a multi-gigabyte memory image.
func (s *sink) File(kind protocol.Kind, path, reason string) error {
	f, err := collector.SecureOpen(path)
	if err != nil {
		s.problem(path + ": " + err.Error())
		return nil
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		s.problem(path + ": " + err.Error())
		return nil
	}
	if !before.Mode().IsRegular() {
		s.problem(path + ": not a regular file")
		return nil
	}
	limit := s.a.artifactLimit(kind)
	if before.Size() > limit {
		s.problem(fmt.Sprintf("%s: file exceeds %s limit", path, humanBytes(limit)))
		return nil
	}
	// The artifact metadata carries the digest and size, so they must be known
	// before the body is sent: hash the file, then stream it from the start.
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, limit+1))
	if err != nil {
		s.problem(path + ": " + err.Error())
		return nil
	}
	if n > limit {
		s.problem(fmt.Sprintf("%s: file exceeds %s limit", path, humanBytes(limit)))
		return nil
	}
	if n != before.Size() {
		s.problem(path + ": file changed while reading")
		return nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		s.problem(path + ": " + err.Error())
		return nil
	}
	after, err := f.Stat()
	if err != nil {
		s.problem(path + ": " + err.Error())
		return nil
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		s.problem(path + ": file changed while reading")
		return nil
	}
	digest := hash.Sum(nil)
	artifact := protocol.Artifact{
		ID:          artifactID(kind, path, digest),
		Kind:        kind,
		Source:      path,
		Reason:      reason,
		SHA256:      hex.EncodeToString(digest),
		Size:        n,
		Mode:        before.Mode().String(),
		ModifiedAt:  before.ModTime().UTC(),
		CollectedAt: time.Now().UTC(),
	}
	if err := s.upload(artifact, f, n); err != nil {
		var rejected rejectError
		if errors.As(err, &rejected) {
			s.problem(path + ": " + err.Error())
			return nil
		}
		return err
	}
	s.count++
	return nil
}

// Bytes implements collector.Sink for synthesized evidence produced in
// memory (parsed API or /proc snapshots rendered as JSON).
func (s *sink) Bytes(kind protocol.Kind, name, reason string, data []byte) error {
	limit := s.a.artifactLimit(kind)
	if int64(len(data)) > limit {
		s.problem(fmt.Sprintf("%s: artifact exceeds %s limit", name, humanBytes(limit)))
		return nil
	}
	hash := sha256.Sum256(data)
	now := time.Now().UTC()
	artifact := protocol.Artifact{
		ID:          artifactID(kind, name, hash[:]),
		Kind:        kind,
		Source:      name,
		Reason:      reason,
		SHA256:      hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		Mode:        "synthesized",
		ModifiedAt:  now,
		CollectedAt: now,
	}
	if err := s.upload(artifact, bytes.NewReader(data), int64(len(data))); err != nil {
		var rejected rejectError
		if errors.As(err, &rejected) {
			s.problem(name + ": " + err.Error())
			return nil
		}
		return err
	}
	s.count++
	return nil
}

// artifactID derives a stable artifact ID from kind, source, and content
// hash. A changed live file is a new version, not a conflicting retry of the
// old bytes, so the content hash participates in the ID.
func artifactID(kind protocol.Kind, source string, hash []byte) string {
	id := sha256.Sum256([]byte(string(kind) + "\x00" + source + "\x00" + hex.EncodeToString(hash)))
	return hex.EncodeToString(id[:])
}

func (s *sink) upload(artifact protocol.Artifact, body io.Reader, size int64) error {
	metadata, _ := json.Marshal(artifact)
	ctx, cancel := context.WithTimeout(s.ctx, uploadTimeout(size))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST",
		s.a.base+"/v1/agent/jobs/"+s.jobID+"/artifacts/"+artifact.ID, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Authorization", "Bearer "+s.a.token)
	req.Header.Set("X-Host-ID", s.a.host)
	req.Header.Set("X-Artifact-Metadata", string(metadata))
	resp, err := s.a.uploadClient.Do(req)
	if err != nil {
		return networkError{err}
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused.
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	switch resp.StatusCode {
	case 200, 201:
		return nil
	case 400, 413:
		return rejectError{fmt.Errorf("server rejected the artifact: HTTP %d", resp.StatusCode)}
	default:
		return networkError{fmt.Errorf("upload HTTP %d", resp.StatusCode)}
	}
}

// humanBytes formats a limit for an operator-facing reason line.
func humanBytes(n int64) string {
	const (
		mib = 1 << 20
		gib = 1 << 30
	)
	switch {
	case n >= gib && n%gib == 0:
		return fmt.Sprintf("%d GiB", n/gib)
	case n >= mib:
		return fmt.Sprintf("%d MiB", n/mib)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
