//go:build darwin

package elev

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// The AppleScript is a constant. Paths are passed as argv and quoted
// with `quoted form of` so user-controlled strings never enter the
// script text.
const osascriptBody = `do shell script (quoted form of item 1 of argv) & " --elevated-op " & (quoted form of item 2 of argv) & " --ops-root " & (quoted form of item 3 of argv) with administrator privileges`

func runElevated(ctx context.Context, exe, opFile, opsRoot string) error {
	cmd := exec.CommandContext(ctx, "osascript",
		"-e", "on run argv",
		"-e", osascriptBody,
		"-e", "end run",
		"--",
		exe,
		opFile,
		opsRoot,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := string(bytes.TrimSpace(stderr.Bytes()))
		if msg != "" {
			return fmt.Errorf("osascript: %w: %s", err, msg)
		}
		return fmt.Errorf("osascript: %w", err)
	}
	return nil
}
