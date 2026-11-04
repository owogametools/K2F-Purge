//go:build windows

package block

import (
	"os/exec"
	"syscall"
)

// createNoWindow is the Windows CREATE_NO_WINDOW process flag.
const createNoWindow = 0x08000000

// hideConsole stops the command from opening a console window, so netsh and
// ipconfig do not flash a terminal during Apply, Remove, or Re-verify.
func hideConsole(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
