//go:build windows

package volatility

import "os/exec"

// Windows has no process groups; the server can still be built and run on
// Windows, but only the wrapper process itself is terminated on timeout.
func setProcessGroup(*exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
