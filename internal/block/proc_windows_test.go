//go:build windows

package block

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestHideConsoleSetsWindowsFlags(t *testing.T) {
	cmd := exec.Command("cmd.exe")
	hideConsole(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr not set")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("HideWindow not set")
	}
	if cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Fatalf("CREATE_NO_WINDOW missing: %#x", cmd.SysProcAttr.CreationFlags)
	}

	// Existing flags are preserved.
	const keep = 0x00000400 // CREATE_NEW_PROCESS_GROUP
	cmd = exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: keep}
	hideConsole(cmd)
	if cmd.SysProcAttr.CreationFlags&keep == 0 {
		t.Fatalf("existing CreationFlags lost: %#x", cmd.SysProcAttr.CreationFlags)
	}
	if cmd.SysProcAttr.CreationFlags&createNoWindow == 0 || !cmd.SysProcAttr.HideWindow {
		t.Fatalf("flags not added: %#v", cmd.SysProcAttr)
	}
}
