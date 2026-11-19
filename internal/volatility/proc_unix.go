//go:build !windows

package volatility

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the wrapper and every Volatility child it starts into
// one process group, so a timeout can terminate the whole tree.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
