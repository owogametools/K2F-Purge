// Package elev detects privilege, relaunches on Windows, and runs a
// whitelist of structured privileged operations on Linux and macOS.
//
// The GUI never interpolates a command string. An elevated child is
// always this same binary with `--elevated-op <file>`.
package elev

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	ModeElevated = "elevated"
	ModeLimited  = "limited"
	ModePerOp    = "per-op"

	opTimeout   = 120 * time.Second
	flagOp      = "--elevated-op"
	flagOpsRoot = "--ops-root"
)

// Sentinel errors the UI can match with errors.Is.
var (
	ErrUACCancelled = errors.New("UAC cancelled")
	ErrUnknownOp    = errors.New("unknown elevated op")
	ErrNotElevated  = errors.New("process is not elevated")
)

// OpRequest is the on-disk contract for `--elevated-op`.
type OpRequest struct {
	Op      string          `json:"op"`
	Payload json.RawMessage `json:"payload"`
}

// OpResponse is written next to the request as `<name>.result.json`.
type OpResponse struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler runs one whitelisted op. payload is the JSON object from the
// request; the return value is placed in OpResponse.Result.
type Handler func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error)

var allowedOps = map[string]struct{}{
	"hosts.apply":     {},
	"hosts.remove":    {},
	"firewall.apply":  {},
	"firewall.remove": {},
	"dns.flush":       {},
	"block.apply":     {},
	"block.remove":    {},
	"clean.apply":     {},
	"clean.restore":   {},
	"clean.purge":     {},
	"registry.export": {},
	"registry.delete": {},
}

var (
	mu       sync.RWMutex
	handlers = map[string]Handler{}

	opsDirOverride string
)

// Register installs a handler for a whitelisted op name. Unknown names
// are rejected so a typo cannot widen the surface.
func Register(op string, h Handler) error {
	if !AllowedOp(op) {
		return fmt.Errorf("%w: %q", ErrUnknownOp, op)
	}
	if h == nil {
		return fmt.Errorf("nil handler for %q", op)
	}
	mu.Lock()
	handlers[op] = h
	mu.Unlock()
	return nil
}

// AllowedOp reports whether op is on the hardcoded whitelist.
func AllowedOp(op string) bool {
	if op == "" || strings.ContainsAny(op, " \t\r\n;|&$<>`(){}[]\\\"'") {
		return false
	}
	_, ok := allowedOps[op]
	return ok
}

// RunPrivileged executes a whitelisted op. When the process is already
// elevated the handler runs in-process. Otherwise the platform helper
// re-execs this binary with `--elevated-op`. Tests always dispatch
// in-process and never trigger UAC / pkexec / osascript.
func RunPrivileged(ctx context.Context, op string, payload any) (json.RawMessage, error) {
	if !AllowedOp(op) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownOp, op)
	}
	raw, err := marshalPayload(payload)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	if testing.Testing() || IsElevated() {
		return dispatch(ctx, op, raw)
	}
	return invokeElevated(ctx, op, raw)
}

// RunOpFromArgs is the child-process entry. If args contain
// `--elevated-op <file>` it runs that op and returns (true, exitCode).
// Callers should invoke this before starting the GUI:
//
//	if handled, code := elev.RunOpFromArgs(os.Args[1:]); handled {
//	    os.Exit(code)
//	}
func RunOpFromArgs(args []string) (handled bool, code int) {
	path, root, ok := findOpArg(args)
	if !ok {
		return false, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := executeOpFile(ctx, path, root); err != nil {
		return true, 1
	}
	return true, 0
}

// findOpArg reads `--elevated-op <file>` and the optional `--ops-root <dir>`
// the parent passes along. The root is needed because the elevated child
// often runs as another user (root) and cannot recompute the caller's cache
// directory with os.UserCacheDir.
func findOpArg(args []string) (path, root string, ok bool) {
	ok = false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == flagOp && i+1 < len(args):
			path, ok = args[i+1], true
			i++
		case strings.HasPrefix(a, flagOp+"="):
			path, ok = strings.TrimPrefix(a, flagOp+"="), true
		case a == flagOpsRoot && i+1 < len(args):
			root = args[i+1]
			i++
		case strings.HasPrefix(a, flagOpsRoot+"="):
			root = strings.TrimPrefix(a, flagOpsRoot+"=")
		}
	}
	return path, root, ok
}

func marshalPayload(payload any) (json.RawMessage, error) {
	if payload == nil {
		return json.RawMessage("{}"), nil
	}
	switch v := payload.(type) {
	case json.RawMessage:
		if len(v) == 0 {
			return json.RawMessage("{}"), nil
		}
		return v, nil
	case []byte:
		if len(v) == 0 {
			return json.RawMessage("{}"), nil
		}
		if !json.Valid(v) {
			return nil, fmt.Errorf("payload is not valid JSON")
		}
		return json.RawMessage(v), nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("payload: %w", err)
		}
		return b, nil
	}
}

func dispatch(ctx context.Context, op string, payload json.RawMessage) (json.RawMessage, error) {
	mu.RLock()
	h := handlers[op]
	mu.RUnlock()
	if h == nil {
		return nil, fmt.Errorf("no handler registered for op %q", op)
	}
	return h(ctx, payload)
}

func invokeElevated(ctx context.Context, op string, payload json.RawMessage) (json.RawMessage, error) {
	path, err := writeOpFile(OpRequest{Op: op, Payload: payload})
	if err != nil {
		return nil, err
	}
	resPath := resultPath(path)
	defer func() {
		_ = os.Remove(path)
		_ = os.Remove(resPath)
	}()

	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("executable: %w", err)
	}
	if err := runElevated(ctx, exe, path, filepath.Dir(path)); err != nil {
		return nil, err
	}
	return readResult(resPath)
}

func writeOpFile(req OpRequest) (string, error) {
	dir, err := opsDir()
	if err != nil {
		return "", err
	}
	name := randomID() + ".json"
	path := filepath.Join(dir, name)
	data, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func executeOpFile(ctx context.Context, path, rootArg string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return writeResult(resultPath(path), OpResponse{OK: false, Error: err.Error()})
	}
	root, err := opsRoot(rootArg)
	if err != nil {
		return writeResult(resultPath(abs), OpResponse{OK: false, Error: err.Error()})
	}
	if !underDir(abs, root) {
		err := fmt.Errorf("op file outside ops directory")
		_ = writeResult(resultPath(abs), OpResponse{OK: false, Error: err.Error()})
		return err
	}
	if st, lerr := os.Lstat(abs); lerr != nil || !st.Mode().IsRegular() {
		err := fmt.Errorf("op file must be a regular file")
		_ = writeResult(resultPath(abs), OpResponse{OK: false, Error: err.Error()})
		return err
	} else if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		err := fmt.Errorf("op file must not be readable by other users")
		_ = writeResult(resultPath(abs), OpResponse{OK: false, Error: err.Error()})
		return err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		_ = writeResult(resultPath(abs), OpResponse{OK: false, Error: err.Error()})
		return err
	}
	var req OpRequest
	if err := json.Unmarshal(data, &req); err != nil {
		err = fmt.Errorf("op file: %w", err)
		_ = writeResult(resultPath(abs), OpResponse{OK: false, Error: err.Error()})
		return err
	}
	if !AllowedOp(req.Op) {
		err := fmt.Errorf("%w: %q", ErrUnknownOp, req.Op)
		_ = writeResult(resultPath(abs), OpResponse{OK: false, Error: err.Error()})
		return err
	}
	out, err := dispatch(ctx, req.Op, req.Payload)
	if err != nil {
		_ = writeResult(resultPath(abs), OpResponse{OK: false, Error: err.Error()})
		return err
	}
	return writeResult(resultPath(abs), OpResponse{OK: true, Result: out})
}

// writeResult is readable by the unprivileged parent: the elevated child
// often runs as another user (root), and a 0600 result would be unreadable
// there. The body only carries status text, never secrets.
func writeResult(path string, resp OpResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func readResult(path string) (json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("elevated result: %w", err)
	}
	var resp OpResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("elevated result: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			return nil, fmt.Errorf("elevated op failed")
		}
		return nil, errors.New(resp.Error)
	}
	return resp.Result, nil
}

func resultPath(opPath string) string {
	dir := filepath.Dir(opPath)
	base := filepath.Base(opPath)
	return filepath.Join(dir, strings.TrimSuffix(base, ".json")+".result.json")
}

func opsDir() (string, error) {
	if opsDirOverride != "" {
		if err := os.MkdirAll(opsDirOverride, 0o700); err != nil {
			return "", err
		}
		return opsDirOverride, nil
	}
	if testing.Testing() {
		return "", fmt.Errorf("ops directory must be overridden in tests")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cache, "k2f-purge", "ops")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// opsRoot resolves the directory that holds the op file. The parent passes
// it on the command line; under pkexec/sudo/osascript the elevated child
// runs as another user, so os.UserCacheDir points at that user's cache and
// would reject the caller's file. The structural check keeps an arbitrary
// directory from being accepted.
func opsRoot(arg string) (string, error) {
	if strings.TrimSpace(arg) == "" {
		return opsDir()
	}
	root, err := filepath.Abs(arg)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	if filepath.Base(root) != "ops" || filepath.Base(filepath.Dir(root)) != "k2f-purge" {
		return "", fmt.Errorf("ops root is not a k2f-purge ops directory: %s", root)
	}
	st, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("ops root is not a directory: %s", root)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("ops root must not be accessible by other users: %s", root)
	}
	return root, nil
}

func underDir(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	sep := string(os.PathSeparator)
	if path == root {
		return true
	}
	prefix := root
	if !strings.HasSuffix(prefix, sep) {
		prefix += sep
	}
	if len(path) == len(root) {
		return strings.EqualFold(path, root)
	}
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(prefix))
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
