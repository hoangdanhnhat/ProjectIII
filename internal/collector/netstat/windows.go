//go:build windows

package netstat

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Table classes for GetExtendedTcpTable / GetExtendedUdpTable (iptypes.h).
const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

// Row layouts from iptypes.h. Field order and sizes are stable Windows ABI.
type mibTCPRowOwnerPID struct {
	State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPID uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr, LocalPort, OwningPID uint32
}

type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

// snapshot reads the extended TCP/UDP tables (both families) and joins the
// owning PIDs with process names from a toolhelp snapshot.
func snapshot() (*Snapshot, error) {
	processes, _ := processNames() // best effort: missing names are omitted
	snap := &Snapshot{SchemaVersion: 2, GeneratedAt: time.Now().UTC()}
	addTCP := func(proto string, local, remote string, lp, rp uint32, state string, pid uint32) {
		snap.Connections = append(snap.Connections, Connection{
			Proto: proto, LocalAddr: local, LocalPort: port(lp),
			RemoteAddr: remote, RemotePort: port(rp), State: state,
			PID: int(pid), Process: processes[pid],
		})
	}
	addUDP := func(proto string, local string, lp uint32, pid uint32) {
		snap.Connections = append(snap.Connections, Connection{
			Proto: proto, LocalAddr: local, LocalPort: port(lp),
			PID: int(pid), Process: processes[pid],
		})
	}
	tcp, err := tcpRows()
	if err != nil {
		return nil, err
	}
	for i := range tcp {
		addTCP("tcp", ipv4(tcp[i].LocalAddr), ipv4(tcp[i].RemoteAddr),
			tcp[i].LocalPort, tcp[i].RemotePort, tcpState(tcp[i].State), tcp[i].OwningPID)
	}
	tcp6, err := tcp6Rows()
	if err != nil {
		return nil, err
	}
	for i := range tcp6 {
		addTCP("tcp6", net.IP(tcp6[i].LocalAddr[:]).String(), net.IP(tcp6[i].RemoteAddr[:]).String(),
			tcp6[i].LocalPort, tcp6[i].RemotePort, tcpState(tcp6[i].State), tcp6[i].OwningPID)
	}
	udp, err := udpRows()
	if err != nil {
		return nil, err
	}
	for i := range udp {
		addUDP("udp", ipv4(udp[i].LocalAddr), udp[i].LocalPort, udp[i].OwningPID)
	}
	udp6, err := udp6Rows()
	if err != nil {
		return nil, err
	}
	for i := range udp6 {
		addUDP("udp6", net.IP(udp6[i].LocalAddr[:]).String(), udp6[i].LocalPort, udp6[i].OwningPID)
	}
	return snap, nil
}

// callTable invokes an extended-table query twice: the first call learns the
// buffer size (returning ERROR_INSUFFICIENT_BUFFER), the second fills it.
func callTable(proc *windows.LazyProc, family, class uint32) ([]byte, error) {
	var size uint32
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(family), uintptr(class), 0)
	if size == 0 {
		return nil, fmt.Errorf("table query returned no size (family %d)", family)
	}
	buf := make([]byte, size)
	if r1, _, err := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1,
		uintptr(family), uintptr(class), 0,
	); r1 != 0 {
		return nil, fmt.Errorf("table query failed (family %d): %w", family, err)
	}
	return buf, nil
}

func rowCount(buf []byte) int {
	return int(*(*uint32)(unsafe.Pointer(&buf[0])))
}

func rowAt[T any](buf []byte, i int) *T {
	return (*T)(unsafe.Pointer(&buf[unsafe.Sizeof(uint32(0))+uintptr(i)*unsafe.Sizeof(*new(T))]))
}

func tcpRows() ([]mibTCPRowOwnerPID, error) {
	buf, err := callTable(procGetExtendedTcpTable, windows.AF_INET, tcpTableOwnerPIDAll)
	if err != nil {
		return nil, err
	}
	rows := make([]mibTCPRowOwnerPID, rowCount(buf))
	for i := range rows {
		rows[i] = *rowAt[mibTCPRowOwnerPID](buf, i)
	}
	return rows, nil
}

func tcp6Rows() ([]mibTCP6RowOwnerPID, error) {
	buf, err := callTable(procGetExtendedTcpTable, windows.AF_INET6, tcpTableOwnerPIDAll)
	if err != nil {
		return nil, err
	}
	rows := make([]mibTCP6RowOwnerPID, rowCount(buf))
	for i := range rows {
		rows[i] = *rowAt[mibTCP6RowOwnerPID](buf, i)
	}
	return rows, nil
}

func udpRows() ([]mibUDPRowOwnerPID, error) {
	buf, err := callTable(procGetExtendedUdpTable, windows.AF_INET, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	rows := make([]mibUDPRowOwnerPID, rowCount(buf))
	for i := range rows {
		rows[i] = *rowAt[mibUDPRowOwnerPID](buf, i)
	}
	return rows, nil
}

func udp6Rows() ([]mibUDP6RowOwnerPID, error) {
	buf, err := callTable(procGetExtendedUdpTable, windows.AF_INET6, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	rows := make([]mibUDP6RowOwnerPID, rowCount(buf))
	for i := range rows {
		rows[i] = *rowAt[mibUDP6RowOwnerPID](buf, i)
	}
	return rows, nil
}

// processNames returns PID -> executable name from a toolhelp snapshot.
func processNames() (map[uint32]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	names := make(map[uint32]string)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return names, nil
	}
	for {
		names[e.ProcessID] = windows.UTF16ToString(e.ExeFile[:])
		if err := windows.Process32Next(snap, &e); err != nil {
			break
		}
	}
	return names, nil
}

// ipv4 renders a DWORD stored in network byte order as a dotted quad.
func ipv4(v uint32) string {
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
}

// port converts a port stored in network byte order in the low 16 bits.
func port(v uint32) int {
	return int(uint16(v&0xff)<<8 | uint16(v>>8)&0xff)
}

// tcpStates maps MIB_TCP_STATE values to netstat-style names.
var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
	6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
	11: "TIME_WAIT", 12: "DELETE_TCB",
}

func tcpState(v uint32) string {
	if name, ok := tcpStates[v]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}
