//go:build windows

package netstat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
)

// psCacheMaxOutput bounds the fallback cmdlet output.
const psCacheMaxOutput = 8 << 20

// dnsCacheViaPowerShell is the fallback when the dnsapi table API is
// unavailable (for example the DNS Client service cannot answer the RPC).
// It runs the built-in Get-DnsClientCache cmdlet — a vetted system tool
// invoked with fixed arguments, like wevtutil in the eventlog collector —
// and parses its JSON, so nothing depends on the console locale.
func dnsCacheViaPowerShell(ctx context.Context) ([]DNSRecord, error) {
	exe, err := exec.LookPath("powershell.exe")
	if err != nil {
		return nil, fmt.Errorf("powershell.exe not found: %w", err)
	}
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(callCtx, exe, "-NoProfile", "-NonInteractive", "-Command",
		"Get-DnsClientCache | Select-Object Entry,Type,Data,TimeToLive | ConvertTo-Json -Compress")
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	data, readErr := readCappedPS(stdout, psCacheMaxOutput)
	if readErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("reading Get-DnsClientCache output: %w", readErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("Get-DnsClientCache failed: %w: %s", waitErr, bytes.TrimSpace(stderr.Bytes()))
	}
	return parsePSCache(data)
}

// readCappedPS mirrors the eventlog collector's capped read: oversize is a
// hard error rather than a silently truncated cache.
func readCappedPS(r io.Reader, limit int) ([]byte, error) {
	var out []byte
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out, nil // EOF or closed pipe: parse what arrived
		}
		if len(out) > limit {
			return nil, fmt.Errorf("output exceeded %d bytes", limit)
		}
	}
}

// psCacheRow is one ConvertTo-Json row. Type arrives as a number (the CIM
// type is UInt16) but is tolerated as a string ("1" or "A") to survive
// cmdlet differences across Windows builds.
type psCacheRow struct {
	Entry      string          `json:"Entry"`
	Type       json.RawMessage `json:"Type"`
	Data       string          `json:"Data"`
	TimeToLive json.Number     `json:"TimeToLive"`
}

func parsePSCache(data []byte) ([]DNSRecord, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil // empty cache
	}
	// ConvertTo-Json emits a single object for one row and an array for
	// more; normalize to a slice.
	var rows []psCacheRow
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, fmt.Errorf("decode Get-DnsClientCache JSON: %w", err)
		}
	} else {
		var one psCacheRow
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, fmt.Errorf("decode Get-DnsClientCache JSON: %w", err)
		}
		rows = []psCacheRow{one}
	}

	var out []DNSRecord
	seen := make(map[string]bool)
	for _, row := range rows {
		typ, ok := psRecordType(row.Type)
		if !ok {
			continue
		}
		name := normalizeName(row.Entry)
		data := normalizeName(row.Data)
		if name == "" || data == "" {
			continue
		}
		key := name + "\x00" + typ + "\x00" + data
		if seen[key] {
			continue
		}
		seen[key] = true
		ttl, _ := row.TimeToLive.Int64()
		out = append(out, DNSRecord{Name: name, Type: typ, TTL: int(ttl), Data: data})
	}
	return out, nil
}

// psRecordType maps the cmdlet's Type field to "A", "AAAA" or "CNAME",
// accepting numeric or textual encodings. Other record types are skipped.
func psRecordType(raw json.RawMessage) (string, bool) {
	s := string(bytes.TrimSpace(raw))
	var num int64
	if err := json.Unmarshal(raw, &num); err == nil {
		switch num {
		case dnsTypeA:
			return "A", true
		case dnsTypeCNAME:
			return "CNAME", true
		case dnsTypeAAAA:
			return "AAAA", true
		}
		return "", false
	}
	unquoted, err := strconv.Unquote(s)
	if err != nil {
		unquoted = s
	}
	switch unquoted {
	case "1", "A":
		return "A", true
	case "5", "CNAME":
		return "CNAME", true
	case "28", "AAAA":
		return "AAAA", true
	}
	return "", false
}

// dnsCacheRecords is the entry point used by Collect: dnsapi first, the
// cmdlet as fallback. Both failing is a reported problem, not a job
// failure — the connection table was already collected.
func dnsCacheRecords(ctx context.Context) ([]DNSRecord, error) {
	records, err := dnsCacheViaAPI()
	if err == nil {
		return records, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	records, psErr := dnsCacheViaPowerShell(ctx)
	if psErr == nil {
		return records, nil
	}
	return nil, fmt.Errorf("dnsapi: %v; powershell fallback: %v", err, psErr)
}
