//go:build windows

package clean

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func registryExport(ctx context.Context, key, dest string) error {
	if err := allowedRegistryKey(key); err != nil {
		return err
	}
	if testing.Testing() {
		body := "Windows Registry Editor Version 5.00\r\n\r\n[" + key + "]\r\n"
		return os.WriteFile(dest, []byte(body), 0o600)
	}
	stdout, stderr, err := runReg(ctx, "reg", "export", key, dest, "/y")
	if err != nil {
		return fmt.Errorf("reg export: %v %s %s", err, strings.TrimSpace(stdout), strings.TrimSpace(stderr))
	}
	return nil
}

func registryDelete(ctx context.Context, key string) error {
	if err := allowedRegistryKey(key); err != nil {
		return err
	}
	if testing.Testing() {
		return nil
	}
	_, stderr, err := runReg(ctx, "reg", "delete", key, "/f")
	if err != nil {
		return fmt.Errorf("reg delete: %v %s", err, strings.TrimSpace(stderr))
	}
	return nil
}

func registryImport(path string) error {
	if testing.Testing() {
		return nil
	}
	_, stderr, err := runReg(context.Background(), "reg", "import", path)
	if err != nil {
		return fmt.Errorf("reg import: %v %s", err, strings.TrimSpace(stderr))
	}
	return nil
}

func runReg(ctx context.Context, name string, args ...string) (string, string, error) {
	if name != "reg" {
		return "", "", fmt.Errorf("refusing non-reg binary %q", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}
