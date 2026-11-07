package agent

import "runtime/debug"

// Version returns the module version when the binary was built from a tagged
// module, otherwise "dev". It is informational inventory metadata.
func Version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return "dev"
}
