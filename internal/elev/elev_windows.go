//go:build windows

package elev

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	swShownormal          = 1
	errorCancelled        = 1223
	seErrAccessDenied     = 5
	shellExecuteOKBarrier = 32
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

// IsElevated reports whether the process token is an elevated administrator.
func IsElevated() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

// Mode is "elevated" or "limited". Windows elevates the whole process.
func Mode() string {
	if IsElevated() {
		return ModeElevated
	}
	return ModeLimited
}

// EnsureElevated relaunches this executable with a UAC prompt. On
// success relaunched is true and the caller should exit. Error 1223
// (user cancelled the prompt) is returned as ErrUACCancelled.
func EnsureElevated(args []string) (bool, error) {
	if IsElevated() {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	params := quoteCmdLine(args)
	if err := shellExecuteRunas(exe, params); err != nil {
		return false, err
	}
	return true, nil
}

func runElevated(ctx context.Context, exe, opFile, opsRoot string) error {
	params := quoteArg(flagOp) + " " + quoteArg(opFile) + " " +
		quoteArg(flagOpsRoot) + " " + quoteArg(opsRoot)
	if err := shellExecuteRunas(exe, params); err != nil {
		return err
	}
	return waitForResultFile(ctx, resultPath(opFile))
}

func shellExecuteRunas(exe, params string) error {
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	var paramPtr *uint16
	if params != "" {
		paramPtr, err = syscall.UTF16PtrFromString(params)
		if err != nil {
			return err
		}
	}
	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(paramPtr)),
		0,
		swShownormal,
	)
	if r > shellExecuteOKBarrier {
		return nil
	}
	if r == errorCancelled || r == seErrAccessDenied || isErrno(callErr, errorCancelled) {
		return ErrUACCancelled
	}
	if callErr != nil && !isErrno(callErr, 0) {
		return fmt.Errorf("ShellExecuteW: %w", callErr)
	}
	return fmt.Errorf("ShellExecuteW failed with code %d", r)
}

func isErrno(err error, n syscall.Errno) bool {
	if err == nil {
		return false
	}
	errno, ok := err.(syscall.Errno)
	return ok && errno == n
}

func waitForResultFile(ctx context.Context, path string) error {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("elevated op timed out")
		case <-tick.C:
			if st, err := os.Stat(path); err == nil && st.Size() > 0 {
				return nil
			}
		}
	}
}

func quoteCmdLine(args []string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	nSlash := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			nSlash++
		case '"':
			b.WriteString(strings.Repeat(`\`, nSlash*2+1))
			b.WriteByte('"')
			nSlash = 0
		default:
			if nSlash > 0 {
				b.WriteString(strings.Repeat(`\`, nSlash))
				nSlash = 0
			}
			b.WriteByte(c)
		}
	}
	if nSlash > 0 {
		b.WriteString(strings.Repeat(`\`, nSlash*2))
	}
	b.WriteByte('"')
	return b.String()
}
