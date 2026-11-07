//go:build windows

package hostrole

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type windowsSource struct{}

// NewSource returns the Windows registry/filesystem probe.
func NewSource() Source { return windowsSource{} }

func (windowsSource) Facts(ctx context.Context) (*Facts, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f := &Facts{Services: make(map[string]Service)}
	f.Hostname, _ = os.Hostname()

	readProductType(f)
	readOSVersion(f)
	readServices(f)
	readShares(f)
	readIIS(f)
	readNTDS(f)
	readSQLInstances(f)
	readExchange(f)

	f.DNSDirectory = probeDirectory(f, filepath.Join(windowsDir(), "System32", "dns"),
		`file:%SystemRoot%\System32\dns`)
	f.DHCPDirectory = probeDirectory(f, filepath.Join(windowsDir(), "System32", "dhcp"),
		`file:%SystemRoot%\System32\dhcp`)
	return f, nil
}

func windowsDir() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return filepath.Clean(root)
	}
	return `C:\Windows`
}

func readProductType(f *Facts) {
	const path = `SYSTEM\CurrentControlSet\Control\ProductOptions`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		f.AddProbeError(`registry:HKLM\`+path, err)
		return
	}
	defer key.Close()
	value, _, err := key.GetStringValue("ProductType")
	if err != nil {
		f.AddProbeError(`registry:HKLM\`+path+`\ProductType`, err)
		return
	}
	f.ProductType = strings.TrimSpace(value)
}

func readOSVersion(f *Facts) {
	const path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		f.AddProbeError(`registry:HKLM\`+path, err)
		return
	}
	defer key.Close()
	if name, _, err := key.GetStringValue("ProductName"); err == nil {
		f.OSName = strings.TrimSpace(name)
	}
	build, _, err := key.GetStringValue("CurrentBuild")
	if err != nil {
		return
	}
	f.OSBuild = strings.TrimSpace(build)
	if ubr, _, err := key.GetIntegerValue("UBR"); err == nil && ubr > 0 && f.OSBuild != "" {
		f.OSBuild = fmt.Sprintf("%s.%d", f.OSBuild, ubr)
	}
}

// serviceNames are the role markers the classifier reads. MSSQL named
// instances are discovered by prefix instead of listing every installed SQL
// instance here.
var serviceNames = map[string]bool{
	"W3SVC":               true,
	"LANMANSERVER":        true,
	"NTDS":                true,
	"NETLOGON":            true,
	"DNS":                 true,
	"DHCPSERVER":          true,
	"MSSQLSERVER":         true,
	"MSEXCHANGEIS":        true,
	"MSEXCHANGETRANSPORT": true,
}

func readServices(f *Facts) {
	const path = `SYSTEM\CurrentControlSet\Services`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		f.AddProbeError(`registry:HKLM\`+path, err)
		return
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		f.AddProbeError(`registry:HKLM\`+path+` (enumeration)`, err)
		return
	}
	sort.Strings(names)
	for _, name := range names {
		upper := strings.ToUpper(name)
		if !serviceNames[upper] && !strings.HasPrefix(upper, "MSSQL$") {
			continue
		}
		svc := Service{Present: true}
		key, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
		if err != nil {
			if !isNotExist(err) {
				f.AddProbeError(`registry:HKLM\`+path+`\`+name, err)
			}
			continue
		}
		if start, _, err := key.GetIntegerValue("Start"); err == nil {
			svc.Start = uint32(start)
			svc.HasStart = true
		}
		key.Close()
		f.Services[name] = svc
	}
}

func readShares(f *Facts) {
	const path = `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if !isNotExist(err) {
			f.AddProbeError(`registry:HKLM\`+path, err)
		}
		return
	}
	defer key.Close()
	names, err := key.ReadValueNames(-1)
	if err != nil {
		f.AddProbeError(`registry:HKLM\`+path+` (values)`, err)
		return
	}
	sort.Strings(names)
	for _, name := range names {
		lines, _, err := key.GetStringsValue(name)
		if err != nil {
			// Some writers store the definition as REG_SZ rather than
			// REG_MULTI_SZ; accept either.
			if single, _, stringErr := key.GetStringValue(name); stringErr == nil {
				lines = []string{single}
			} else {
				f.AddProbeError(`registry:HKLM\`+path+`\`+name, err)
				continue
			}
		}
		f.Shares = append(f.Shares, ParseShareValue(name, lines))
	}
	sortShares(f.Shares)
}

func readIIS(f *Facts) {
	iis := &IISFacts{}
	const path = `SOFTWARE\Microsoft\InetStp`
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE); err == nil {
		iis.Registry = true
		if major, _, err := key.GetIntegerValue("MajorVersion"); err == nil {
			iis.MajorVersion = int(major)
		}
		key.Close()
	} else if !isNotExist(err) {
		f.AddProbeError(`registry:HKLM\`+path, err)
	}
	config := filepath.Join(windowsDir(), "System32", "inetsrv", "config", "applicationHost.config")
	iis.ConfigPresent = probeFile(f, config,
		`file:%SystemRoot%\System32\inetsrv\config\applicationHost.config`)
	if iis.Registry || iis.ConfigPresent {
		f.IIS = iis
	}
}

func readNTDS(f *Facts) {
	path := filepath.Join(windowsDir(), "NTDS", "ntds.dit")
	f.NTDS = probeFile(f, path, `file:%SystemRoot%\NTDS\ntds.dit`)
}

func readSQLInstances(f *Facts) {
	paths := []string{
		`SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`,
		`SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL`,
	}
	var instances []string
	for _, path := range paths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			if !isNotExist(err) {
				f.AddProbeError(`registry:HKLM\`+path, err)
			}
			continue
		}
		names, err := key.ReadValueNames(-1)
		key.Close()
		if err != nil {
			f.AddProbeError(`registry:HKLM\`+path+` (values)`, err)
			continue
		}
		instances = append(instances, names...)
	}
	f.SQLInstances = dedupeSorted(instances)
}

func readExchange(f *Facts) {
	const path = `SOFTWARE\Microsoft\ExchangeServer`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if !isNotExist(err) {
			f.AddProbeError(`registry:HKLM\`+path, err)
		}
		return
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		f.AddProbeError(`registry:HKLM\`+path+` (enumeration)`, err)
		return
	}
	best := 0
	for _, name := range names {
		if len(name) < 2 || (name[0] != 'v' && name[0] != 'V') {
			continue
		}
		major, err := strconv.Atoi(name[1:])
		if err != nil || major < 8 {
			continue
		}
		setup, err := registry.OpenKey(root, name+`\Setup`, registry.QUERY_VALUE)
		if err != nil {
			if !isNotExist(err) {
				f.AddProbeError(`registry:HKLM\`+path+`\`+name+`\Setup`, err)
			}
			continue
		}
		setup.Close()
		if major > best {
			best = major
			f.Exchange = name
		}
	}
}

// probeFile checks metadata only. ntds.dit is held open by AD DS and cannot
// be opened for reading on a live domain controller, so the role profile must
// not depend on opening it.
func probeFile(f *Facts, path, source string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			f.AddProbeError(source, err)
		}
		return false
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		f.AddProbeError(source, errors.New("symlink, junction, or reparse point is not allowed"))
		return false
	}
	if !info.Mode().IsRegular() {
		f.AddProbeError(source, errors.New("not a regular file"))
		return false
	}
	return true
}

func probeDirectory(f *Facts, path, source string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			f.AddProbeError(source, err)
		}
		return false
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		f.AddProbeError(source, errors.New("symlink, junction, or reparse point is not allowed"))
		return false
	}
	if !info.IsDir() {
		f.AddProbeError(source, errors.New("not a directory"))
		return false
	}
	return true
}

func isNotExist(err error) bool {
	return errors.Is(err, registry.ErrNotExist) || os.IsNotExist(err)
}
