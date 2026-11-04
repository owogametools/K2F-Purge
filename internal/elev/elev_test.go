package elev

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnknownOpRejected(t *testing.T) {
	for _, op := range []string{
		"rm -rf /",
		"curl",
		"hosts.apply; wget evil",
		"",
		"not.an.op",
		"hosts.apply\nfirewall.apply",
	} {
		if AllowedOp(op) {
			t.Fatalf("allowed unexpected op %q", op)
		}
		if _, err := RunPrivileged(context.Background(), op, nil); err == nil {
			t.Fatalf("RunPrivileged(%q) succeeded", op)
		} else if !errors.Is(err, ErrUnknownOp) && !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("RunPrivileged(%q): %v", op, err)
		}
		if err := Register(op, func(context.Context, json.RawMessage) (json.RawMessage, error) {
			t.Fatal("handler must not run")
			return nil, nil
		}); err == nil {
			t.Fatalf("Register(%q) should fail", op)
		}
	}
}

func TestWhitelistKnownOps(t *testing.T) {
	for op := range allowedOps {
		if !AllowedOp(op) {
			t.Fatalf("%q should be allowed", op)
		}
	}
}

func TestRunOpFromArgsNoFlag(t *testing.T) {
	handled, code := RunOpFromArgs([]string{"--scan", "x"})
	if handled || code != 0 {
		t.Fatalf("handled=%v code=%d", handled, code)
	}
}

func TestOpFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	opsDirOverride = dir
	t.Cleanup(func() { opsDirOverride = "" })

	const op = "hosts.apply"
	if err := Register(op, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var got map[string]string
		if err := json.Unmarshal(payload, &got); err != nil {
			return nil, err
		}
		if got["k"] != "v" {
			t.Fatalf("payload %+v", got)
		}
		return json.Marshal(map[string]any{"ok": true, "n": 1})
	}); err != nil {
		t.Fatal(err)
	}

	req := OpRequest{Op: op, Payload: json.RawMessage(`{"k":"v"}`)}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "abc.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	handled, code := RunOpFromArgs([]string{flagOp, path})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d", handled, code)
	}
	data, err := os.ReadFile(resultPath(path))
	if err != nil {
		t.Fatal(err)
	}
	var resp OpResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("resp %+v", resp)
	}
	if !strings.Contains(string(resp.Result), `"ok":true`) {
		t.Fatalf("result %s", resp.Result)
	}

	out, err := RunPrivileged(context.Background(), op, map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"n":1`) {
		t.Fatalf("in-process result %s", out)
	}
}

func TestOpFileRejectsUnknownAndOutsideDir(t *testing.T) {
	dir := t.TempDir()
	opsDirOverride = dir
	t.Cleanup(func() { opsDirOverride = "" })

	req := OpRequest{Op: "curl http://evil.example", Payload: json.RawMessage(`{}`)}
	raw, _ := json.Marshal(req)
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	handled, code := RunOpFromArgs([]string{flagOp, path})
	if !handled || code == 0 {
		t.Fatalf("unknown op should fail: handled=%v code=%d", handled, code)
	}
	data, err := os.ReadFile(resultPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"ok":false`) {
		t.Fatalf("result %s", data)
	}

	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	handled, code = RunOpFromArgs([]string{flagOp, outside})
	if !handled || code == 0 {
		t.Fatalf("outside op file should fail: handled=%v code=%d", handled, code)
	}
}

func TestModeAndEnsureElevatedCompile(t *testing.T) {
	_ = IsElevated()
	m := Mode()
	if m != ModeElevated && m != ModeLimited && m != ModePerOp {
		t.Fatalf("unexpected mode %q", m)
	}
	// Never call EnsureElevated here: on Windows it would raise UAC.
	if IsElevated() {
		relaunched, err := EnsureElevated(nil)
		if err != nil {
			t.Fatal(err)
		}
		if relaunched {
			t.Fatal("already elevated, must not relaunch")
		}
	}
}

func TestOpFileWithExplicitOpsRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "k2f-purge", "ops")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	opsDirOverride = root
	t.Cleanup(func() { opsDirOverride = "" })

	const op = "hosts.apply"
	if err := Register(op, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		return json.Marshal(map[string]any{"ok": true})
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(OpRequest{Op: op, Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "abc.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	handled, code := RunOpFromArgs([]string{flagOp, path, flagOpsRoot, root})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d", handled, code)
	}
}

func TestOpsRootRejectsWrongShape(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-ops")
	if err := os.MkdirAll(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := opsRoot(bad); err == nil {
		t.Fatal("a directory that is not <x>/k2f-purge/ops must be refused")
	}
	if p, root, ok := findOpArg([]string{flagOp + "=/tmp/a.json", flagOpsRoot + "=/tmp/ops"}); !ok || p != "/tmp/a.json" || root != "/tmp/ops" {
		t.Fatalf("findOpArg = %q %q %v", p, root, ok)
	}
}
