//go:build windows

package clean

import (
	"errors"
	"syscall"
	"unsafe"
)

const (
	errorSharingViolation    syscall.Errno = 32
	moveFileDelayUntilReboot               = 0x4
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procMoveFileExW = kernel32.NewProc("MoveFileExW")
)

func isSharingViolation(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == errorSharingViolation
	}
	return false
}

func scheduleDeleteOnReboot(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, callErr := procMoveFileExW.Call(uintptr(unsafe.Pointer(p)), 0, moveFileDelayUntilReboot)
	if r == 0 {
		if callErr != nil {
			return callErr
		}
		return syscall.EINVAL
	}
	return nil
}
