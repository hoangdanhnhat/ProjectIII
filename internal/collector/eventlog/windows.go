//go:build windows

package eventlog

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// maxChannelOutput bounds one channel's wevtutil output at the 10 MiB
// artifact limit; a snapshot larger than that is abandoned, not truncated.
const maxChannelOutput = 10 << 20

// errOutputTooLarge marks an oversized channel snapshot.
var errOutputTooLarge = errors.New("wevtutil output exceeded the 10 MiB limit")

// collectChannels runs wevtutil for each configured channel and uploads each
// channel as one artifact. Channel-level failures (bad channel name, access
// denied on Security, oversized output) are recorded as problems and do not
// stop the remaining channels; only transport errors abort.
func (s *scenario) collectChannels(ctx context.Context, job *protocol.Job, sink collector.Sink) error {
	for _, ch := range s.channels {
		if err := validateChannel(ch); err != nil {
			sink.Problem("channel %q: %v", ch, err)
			continue
		}
		data, err := runWevtutil(ctx, ch, job.Since)
		if err != nil {
			sink.Problem("channel %s: %v", ch, err)
			continue
		}
		events, err := decodeEvents(data)
		if err != nil {
			sink.Problem("channel %s: output decode failed: %v", ch, err)
			continue
		}
		reason := "event log snapshot (live collection)"
		if job.Since != nil {
			reason = "event log snapshot since requested time"
		}
		batch := &ChannelEvents{
			SchemaVersion: 1,
			Channel:       ch,
			CapturedAt:    time.Now().UTC(),
			Since:         job.Since,
			Events:        events,
		}
		if err := sink.Bytes(protocol.KindEventLog, "eventlog_"+safeFilename(ch)+".json", reason, Render(batch)); err != nil {
			return err // transport error: abort, job stays running for retry
		}
	}
	return nil
}

// runWevtutil collects one channel:
//
//	wevtutil qe <channel> /f:xml /rd:true /uni:true
//	plus /q:<xpath> when the job has a Since bound
//
// /rd:true returns newest first so a Since filter converges without reading
// the whole history; /uni:true forces Unicode output so decoding does not
// depend on the console code page; /f:xml is the parseable form.
func runWevtutil(ctx context.Context, channel string, since *time.Time) ([]byte, error) {
	exe, err := exec.LookPath("wevtutil")
	if err != nil {
		return nil, fmt.Errorf("wevtutil not found: %w", err)
	}
	args := []string{"qe", channel, "/f:xml", "/rd:true", "/uni:true"}
	if since != nil {
		args = append(args, "/q:"+sinceQuery(*since))
	}
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stderr := new(bytes.Buffer)
	cmd := exec.CommandContext(callCtx, exe, args...)
	cmd.Stderr = stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	data, readErr := readCapped(stdout, maxChannelOutput)
	// Whether or not the read succeeded we must reap the process; a size
	// overrun is terminated through the callCtx cancel embedded in
	// CommandContext before Wait returns.
	if readErr != nil {
		cancel() // kill wevtutil if it is still streaming
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		if errors.Is(readErr, errOutputTooLarge) {
			return nil, errOutputTooLarge
		}
		return nil, fmt.Errorf("reading wevtutil output: %w", readErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("wevtutil failed: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return decodeWevtutilOutput(data), nil
}

// readCapped reads from r until EOF or the limit. Oversize is a hard error
// so the caller can report and move on instead of uploading a partial
// snapshot.
func readCapped(r io.Reader, limit int) ([]byte, error) {
	var out []byte
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			// After a cancel the pipe may report an OS error before EOF;
			// that path only matters when the limit was already exceeded.
			if len(out) > limit {
				return nil, errOutputTooLarge
			}
			return nil, err
		}
		if len(out) > limit {
			return nil, errOutputTooLarge
		}
	}
}

// decodeWevtutilOutput converts UTF-16 output (which /uni:true selects) to
// UTF-8, detecting the byte order from the BOM or, when the BOM is missing,
// from the interleaved zero bytes typical of Latin text in UTF-16LE.
func decodeWevtutilOutput(data []byte) []byte {
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		return utf16Decode(data[2:], false)
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		return utf16Decode(data[2:], true)
	case len(data) >= 2 && data[1] == 0 && data[0] != 0:
		return utf16Decode(data, false) // UTF-16LE without a BOM
	default:
		return data
	}
}

func utf16Decode(data []byte, big bool) []byte {
	units := make([]uint16, len(data)/2)
	for i := range units {
		if big {
			units[i] = binary.BigEndian.Uint16(data[i*2:])
		} else {
			units[i] = binary.LittleEndian.Uint16(data[i*2:])
		}
	}
	return []byte(string(utf16.Decode(units)))
}
