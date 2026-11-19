//go:build windows

package memory

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GlobalMemoryStatusEx is not wrapped by x/sys/windows, so it is called
// through a lazily resolved kernel32 entry point.
var procGlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type tokenElevation struct {
	TokenIsElevated uint32
}

// probeHost reads physical memory size, free space on the -memory-out volume
// and the process elevation state. All three are prerequisites for a capture
// that will actually succeed.
func probeHost(dir string) (Probe, error) {
	var p Probe
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	ok, _, callErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if ok == 0 {
		return p, fmt.Errorf("GlobalMemoryStatusEx: %w", callErr)
	}
	p.TotalMemory = int64(status.TotalPhys)

	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return p, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(dirPtr, &free, &total, &totalFree); err != nil {
		return p, fmt.Errorf("GetDiskFreeSpaceEx: %w", err)
	}
	p.FreeDisk = int64(free)

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return p, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()
	var elevation tokenElevation
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &size); err != nil {
		return p, fmt.Errorf("GetTokenInformation: %w", err)
	}
	p.Elevated = elevation.TokenIsElevated != 0
	return p, nil
}
