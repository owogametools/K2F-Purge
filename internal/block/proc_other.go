//go:build !windows

package block

import "os/exec"

// hideConsole is a no-op outside Windows, where child processes do not get a
// console window from exec.CommandContext.
func hideConsole(cmd *exec.Cmd) {}
