//go:build !windows

package clean

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func registryExport(ctx context.Context, key, dest string) error {
	if err := allowedRegistryKey(key); err != nil {
		return err
	}
	if testing.Testing() {
		body := "Windows Registry Editor Version 5.00\n\n[" + key + "]\n"
		return os.WriteFile(dest, []byte(body), 0o600)
	}
	return fmt.Errorf("registry export is only supported on Windows")
}

func registryDelete(ctx context.Context, key string) error {
	if err := allowedRegistryKey(key); err != nil {
		return err
	}
	if testing.Testing() {
		return nil
	}
	return fmt.Errorf("registry delete is only supported on Windows")
}

func registryImport(path string) error {
	if testing.Testing() {
		return nil
	}
	return fmt.Errorf("registry import is only supported on Windows")
}
