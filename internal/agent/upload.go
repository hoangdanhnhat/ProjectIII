package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// maxArtifact matches the server's per-artifact size limit.
const maxArtifact = 10 << 20

// networkError marks transport failures. The sink returns them so collectors
// abort and the job stays running for a retry, instead of recording every
// remaining file as a failure.
type networkError struct{ error }

// File implements collector.Sink: open without following symlinks, verify the
// file did not change while reading, hash the exact bytes sent, and upload.
// File-level problems are recorded on the sink and do not abort collection;
// only transport errors are returned.
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
	data, err := io.ReadAll(io.LimitReader(f, maxArtifact+1))
	if err != nil {
		s.problem(path + ": " + err.Error())
		return nil
	}
	if len(data) > maxArtifact {
		s.problem(path + ": file exceeds 10 MiB limit")
		return nil
	}
	after, err := f.Stat()
	if err != nil {
		s.problem(path + ": " + err.Error())
		return nil
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() || int64(len(data)) != after.Size() {
		s.problem(path + ": file changed while reading")
		return nil
	}
	hash := sha256.Sum256(data)
	artifact := protocol.Artifact{
		ID:          artifactID(kind, path, hash),
		Kind:        kind,
		Source:      path,
		Reason:      reason,
		SHA256:      hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		Mode:        before.Mode().String(),
		ModifiedAt:  before.ModTime().UTC(),
		CollectedAt: time.Now().UTC(),
	}
	if err := s.upload(artifact, data); err != nil {
		return err
	}
	s.count++
	return nil
}

// Bytes implements collector.Sink for synthesized evidence produced in
// memory (parsed API or /proc snapshots rendered as JSON).
func (s *sink) Bytes(kind protocol.Kind, name, reason string, data []byte) error {
	if len(data) > maxArtifact {
		s.problem(name + ": artifact exceeds 10 MiB limit")
		return nil
	}
	hash := sha256.Sum256(data)
	now := time.Now().UTC()
	artifact := protocol.Artifact{
		ID:          artifactID(kind, name, hash),
		Kind:        kind,
		Source:      name,
		Reason:      reason,
		SHA256:      hex.EncodeToString(hash[:]),
		Size:        int64(len(data)),
		Mode:        "synthesized",
		ModifiedAt:  now,
		CollectedAt: now,
	}
	if err := s.upload(artifact, data); err != nil {
		return err
	}
	s.count++
	return nil
}

// artifactID derives a stable artifact ID from kind, source, and content
// hash. A changed live file is a new version, not a conflicting retry of the
// old bytes, so the content hash participates in the ID.
func artifactID(kind protocol.Kind, source string, hash [sha256.Size]byte) string {
	id := sha256.Sum256([]byte(string(kind) + "\x00" + source + "\x00" + hex.EncodeToString(hash[:])))
	return hex.EncodeToString(id[:])
}

func (s *sink) upload(artifact protocol.Artifact, data []byte) error {
	metadata, _ := json.Marshal(artifact)
	req, err := http.NewRequestWithContext(s.ctx, "POST",
		s.a.base+"/v1/agent/jobs/"+s.jobID+"/artifacts/"+artifact.ID, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.a.token)
	req.Header.Set("X-Host-ID", s.a.host)
	req.Header.Set("X-Artifact-Metadata", string(metadata))
	resp, err := s.a.client.Do(req)
	if err != nil {
		return networkError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return networkError{fmt.Errorf("upload HTTP %d", resp.StatusCode)}
	}
	return nil
}
