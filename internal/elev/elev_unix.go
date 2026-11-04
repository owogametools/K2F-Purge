//go:build linux || darwin

package elev

import "os"

// IsElevated reports whether the process is running as root.
func IsElevated() bool {
	return os.Geteuid() == 0
}

// Mode is "elevated" when already root, otherwise "per-op". The GUI
// stays unprivileged; each privileged action re-execs via pkexec,
// sudo -n, or osascript.
func Mode() string {
	if IsElevated() {
		return ModeElevated
	}
	return ModePerOp
}

// EnsureElevated is a no-op on Unix: restarting the GUI as root is
// unreliable on Wayland and macOS window server.
func EnsureElevated(args []string) (bool, error) {
	return false, nil
}
