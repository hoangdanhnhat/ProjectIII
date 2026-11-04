//go:build windows

package netstat

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dnsapi.dll exports for reading the DNS client resolver cache without
// generating any network traffic.
var (
	dnsapiDLL                = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable = dnsapiDLL.NewProc("DnsGetCacheDataTable")
	procDnsQueryW            = dnsapiDLL.NewProc("DnsQuery_W")
	procDnsRecordListFree    = dnsapiDLL.NewProc("DnsRecordListFree")
	procDnsFree              = dnsapiDLL.NewProc("DnsFree")
)

// Query options for DnsQuery_W (windns.h): NO_WIRE_QUERY | NO_LOCAL_NAME |
// NO_HOSTS_FILE | NO_NETBT. The combination guarantees a forensic read of
// the resolver cache answers only from the cache and never touches the
// network, the HOSTS file, NetBT, or the local machine name.
const dnsQueryCacheOnly = 0x10 | 0x20 | 0x40 | 0x80

// Resource record types of interest (windns.h DNS_TYPE_*).
const (
	dnsTypeA     = 1
	dnsTypeCNAME = 5
	dnsTypeAAAA  = 28
)

// DNS_FREE_TYPE value for DnsFree when releasing flat allocations.
const dnsFreeFlat = 0

// dnsCacheEntry mirrors DNS_CACHE_ENTRY (windns.h): pNext, pszName, wType,
// wDataLength, dwFlags — 24 bytes on x64.
type dnsCacheEntry struct {
	Next *dnsCacheEntry
	Name *uint16
	Type uint16
	_    uint16 // wDataLength
	_    uint32 // dwFlags
}

// dnsRecordW mirrors the fixed part of DNS_RECORDW (windns.h) through the
// start of the Data union: pNext, pName, wType, wDataLength, Flags, dwTtl,
// dwReserved, then Data at offset 32. Data holds the A address (first 4
// bytes, network order), the AAAA address (16 bytes), or a pointer to the
// CNAME target string.
type dnsRecordW struct {
	Next *dnsRecordW
	Name *uint16
	Type uint16
	_    uint16 // wDataLength
	_    uint32 // Flags
	TTL  uint32
	_    uint32 // dwReserved
	Data [16]byte
}

// maxDNSCacheEntries bounds the collected cache: a busy resolver holds a
// few hundred entries, well under this cap, and each contributes only a
// small JSON record.
const maxDNSCacheEntries = 1000

// dnsCacheViaAPI reads the resolver cache with dnsapi.dll:
// DnsGetCacheDataTable lists the cached (name, type) pairs, then every
// interesting name is read back with DnsQuery_W in cache-only mode, which
// returns the full record chain for that name (CNAME followed by A/AAAA).
func dnsCacheViaAPI() ([]DNSRecord, error) {
	var head *dnsCacheEntry
	r1, _, err := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if r1 == 0 {
		return nil, fmt.Errorf("DnsGetCacheDataTable failed: %v", err)
	}
	defer freeCacheTable(head)

	var out []DNSRecord
	seen := make(map[string]bool)
	for e := head; e != nil; e = e.Next {
		if len(seen) >= maxDNSCacheEntries {
			break
		}
		if e.Name == nil {
			continue
		}
		switch e.Type {
		case dnsTypeA, dnsTypeCNAME, dnsTypeAAAA:
		default:
			continue // NS, SOA, PTR and friends are not collected
		}
		name := normalizeName(windows.UTF16PtrToString(e.Name))
		if name == "" {
			continue
		}
		// One cache row per (name, type): a dual-stack host caches A and
		// AAAA for the same name as separate entries, and both are read.
		key := name + "\x00" + strconv.Itoa(int(e.Type))
		if seen[key] {
			continue
		}
		seen[key] = true
		records, err := dnsQueryCached(name, e.Type)
		if err != nil {
			// A single unreadable name (e.g. evicted mid-read) must not
			// discard the rest of the cache snapshot.
			continue
		}
		out = append(out, records...)
	}
	return dedupeRecords(out), nil
}

// dnsQueryCached returns the cached records for one name and query type.
// The result list may contain the CNAME edge plus the target's address
// records when the cache holds a chain.
func dnsQueryCached(name string, qtype uint16) ([]DNSRecord, error) {
	pname, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var result *dnsRecordW
	status, _, _ := procDnsQueryW.Call(
		uintptr(unsafe.Pointer(pname)),
		uintptr(qtype),
		uintptr(dnsQueryCacheOnly),
		0, // no server list
		uintptr(unsafe.Pointer(&result)),
		0,
	)
	if status != 0 {
		return nil, fmt.Errorf("DnsQuery_W(%s, %d) status %d", name, qtype, status)
	}
	if result == nil {
		return nil, nil
	}
	// DnsQuery_W results are real DNS_RECORDW lists: DnsRecordListFree with
	// DnsFreeRecordList (1) is the documented way to release them.
	defer procDnsRecordListFree.Call(uintptr(unsafe.Pointer(result)), 1)

	var out []DNSRecord
	for r := result; r != nil; r = r.Next {
		if rec, ok := convertRecord(r); ok {
			out = append(out, rec)
		}
	}
	return out, nil
}

// convertRecord renders one DNS_RECORDW as a DNSRecord.
func convertRecord(r *dnsRecordW) (DNSRecord, bool) {
	name := normalizeName(windows.UTF16PtrToString(r.Name))
	if name == "" {
		return DNSRecord{}, false
	}
	rec := DNSRecord{Name: name, TTL: int(r.TTL)}
	switch r.Type {
	case dnsTypeA:
		v := binary.LittleEndian.Uint32(r.Data[:4]) // in-memory wire order
		rec.Type = "A"
		rec.Data = ipv4(v)
	case dnsTypeAAAA:
		rec.Type = "AAAA"
		rec.Data = net.IP(r.Data[:16]).String()
	case dnsTypeCNAME:
		p := *(**uint16)(unsafe.Pointer(&r.Data[0]))
		if p == nil {
			return DNSRecord{}, false
		}
		rec.Type = "CNAME"
		rec.Data = normalizeName(windows.UTF16PtrToString(p))
	default:
		return DNSRecord{}, false
	}
	return rec, true
}

// freeCacheTable releases a DnsGetCacheDataTable list. DnsRecordListFree
// must NOT be used here: it frees type-specific Data pointers (CNAME, NS,
// PTR) at offset 32, past the end of the 24-byte DNS_CACHE_ENTRY
// allocation. The safe pattern is DnsFree with DnsFreeFlat on each name
// string and each entry node.
func freeCacheTable(head *dnsCacheEntry) {
	for e := head; e != nil; {
		next := e.Next
		if e.Name != nil {
			procDnsFree.Call(uintptr(unsafe.Pointer(e.Name)), dnsFreeFlat)
		}
		procDnsFree.Call(uintptr(unsafe.Pointer(e)), dnsFreeFlat)
		e = next
	}
}

// dedupeRecords removes duplicate (name, type, data) rows that can appear
// when both a chain query and a direct entry describe the same record.
func dedupeRecords(records []DNSRecord) []DNSRecord {
	seen := make(map[string]bool, len(records))
	out := records[:0]
	for _, r := range records {
		key := r.Name + "\x00" + r.Type + "\x00" + r.Data
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}
