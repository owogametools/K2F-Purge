//go:build !windows

package scan

func registrySupported() bool { return false }

func registryQueryPlatform(key string) (bool, error) {
	return false, nil
}
