//go:build windows

package scan

import (
	"os/exec"
	"strings"
)

func registrySupported() bool { return true }

func registryQueryPlatform(key string) (bool, error) {
	if key == "" || forbiddenRegistryKey(key) {
		return false, nil
	}
	cmd := exec.Command("reg", "query", key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// `reg query` exits 1 when the key is absent.
		return false, nil
	}
	return len(strings.TrimSpace(string(out))) > 0, nil
}
