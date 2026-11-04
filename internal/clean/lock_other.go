//go:build !windows

package clean

import "fmt"

func isSharingViolation(err error) bool {
	return false
}

func scheduleDeleteOnReboot(path string) error {
	return fmt.Errorf("delay-until-reboot is not supported on this OS: %s", path)
}
