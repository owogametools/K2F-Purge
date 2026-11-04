//go:build linux

package elev

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

func runElevated(ctx context.Context, exe, opFile, opsRoot string) error {
	if err := runBin(ctx, "pkexec", exe, flagOp, opFile, flagOpsRoot, opsRoot); err == nil {
		return nil
	} else if ctx.Err() != nil {
		return err
	}
	if err := runBin(ctx, "sudo", "-n", exe, flagOp, opFile, flagOpsRoot, opsRoot); err != nil {
		return fmt.Errorf("pkexec and sudo -n failed: %w", err)
	}
	return nil
}

func runBin(ctx context.Context, name string, args ...string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%s: %w: %s", name, err, stringsTrim(stderr.Bytes()))
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func stringsTrim(b []byte) string {
	n := len(b)
	if n > 512 {
		n = 512
	}
	return string(bytes.TrimSpace(b[:n]))
}
