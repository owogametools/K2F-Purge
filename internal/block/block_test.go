package block

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestPlanDefaultsAndIPValidation(t *testing.T) {
	p := Plan(nil, nil)
	if !p.UseHosts || !p.UseFirewall || !p.Persist || !p.FlushDNS {
		t.Fatalf("flags %+v", p)
	}
	if p.BlockTBSBrowser || len(p.ProgramPaths) != 0 {
		t.Fatalf("tbs_browser block must be opt-in: %+v", p)
	}
	if len(p.Domains) != 5 {
		t.Fatalf("domains %v", p.Domains)
	}
	if len(p.IPs) != 2 {
		t.Fatalf("ips %v", p.IPs)
	}
	p = Plan([]string{"insightjs.com", "http://evil.example/; rm -rf /", "not a host", "WWW.INSIGHTJS.ORG"},
		[]string{"89.127.233.127", "not-an-ip", "999.1.2.3", "127.0.0.1", "89.127.233.127"})
	for _, d := range p.Domains {
		if strings.ContainsAny(d, " ;/") {
			t.Fatalf("unsanitized domain %q", d)
		}
	}
	if len(p.Domains) != 2 {
		t.Fatalf("domains %v", p.Domains)
	}
	if len(p.IPs) != 2 {
		t.Fatalf("ips %v (invalid must be dropped)", p.IPs)
	}
	for _, ip := range p.IPs {
		if ip == "not-an-ip" || ip == "999.1.2.3" {
			t.Fatalf("invalid IP kept: %v", p.IPs)
		}
	}
}

func TestHostsPreservesUnrelatedAndIdempotent(t *testing.T) {
	path := withHosts(t, "127.0.0.1 localhost\n::1 localhost\n# keep me\n")
	p := Plan([]string{"insightjs.com"}, nil)
	p.UseFirewall = false
	p.FlushDNS = false
	st, err := Apply(context.Background(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !st.HostsApplied {
		t.Fatalf("status %+v", st)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("127.0.0.1 localhost")) || !bytes.Contains(data, []byte("# keep me")) {
		t.Fatalf("lost original:\n%s", data)
	}
	if !bytes.Contains(data, []byte(markerBegin)) || !bytes.Contains(data, []byte("0.0.0.0 insightjs.com")) {
		t.Fatalf("missing block:\n%s", data)
	}
	first := append([]byte(nil), data...)
	st, err = Apply(context.Background(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if !bytes.Equal(first, second) {
		t.Fatalf("not idempotent\n---\n%s\n---\n%s", first, second)
	}
	backups, _ := filepath.Glob(path + ".k2f-backup-*")
	if len(backups) == 0 {
		t.Fatal("expected a backup")
	}

	st, err = Remove(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	third, _ := os.ReadFile(path)
	if bytes.Contains(third, []byte("K2F PURGE")) {
		t.Fatalf("marker remains:\n%s", third)
	}
	if !bytes.Contains(third, []byte("127.0.0.1 localhost")) || !bytes.Contains(third, []byte("# keep me")) {
		t.Fatalf("lost original after remove:\n%s", third)
	}
}

func TestHostsCRLFPreserved(t *testing.T) {
	path := withHosts(t, "127.0.0.1 localhost\r\n# keep\r\n")
	if err := applyHosts([]string{"insightjs.org"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Contains(data, []byte("localhost\r\n")) {
		t.Fatalf("CRLF lost:\n%q", data)
	}
	if bytes.Contains(data, []byte("localhost\n#")) && !bytes.Contains(data, []byte("localhost\r\n#")) {
		t.Fatalf("mixed newlines:\n%q", data)
	}
	nlCount := bytes.Count(data, []byte("\n"))
	crlfCount := bytes.Count(data, []byte("\r\n"))
	if crlfCount == 0 || crlfCount != nlCount {
		t.Fatalf("expected only CRLF, crlf=%d nl=%d\n%q", crlfCount, nlCount, data)
	}
	if err := removeHosts(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, []byte("127.0.0.1 localhost\r\n# keep\r\n")) {
		t.Fatalf("remove changed unrelated bytes:\n%q", after)
	}
}

func TestHostsMissingMarkersAndMissingFile(t *testing.T) {
	path := withHosts(t, "127.0.0.1 localhost\n")
	if err := removeHosts(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "127.0.0.1 localhost\n" {
		t.Fatalf("remove without markers changed file: %q", data)
	}

	missing := filepath.Join(t.TempDir(), "hosts")
	hostsPathOverride = missing
	t.Cleanup(func() { hostsPathOverride = "" })
	if err := applyHosts([]string{"insightjs.com"}); err != nil {
		t.Fatal(err)
	}
	created, err := os.ReadFile(missing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(created, []byte(markerBegin)) {
		t.Fatalf("expected new block, got %q", created)
	}
	if err := removeHosts(); err != nil {
		t.Fatal(err)
	}
}

func TestHostsMalformedEndMarker(t *testing.T) {
	withHosts(t, "127.0.0.1 localhost\n# >>> K2F PURGE BLOCK BEGIN v1 — managed by K2F PURGE, do not edit\n0.0.0.0 x\n")
	if err := applyHosts([]string{"insightjs.com"}); err == nil {
		t.Fatal("expected error for missing end marker")
	}
}

func TestFirewallRunnerErrorSurfaced(t *testing.T) {
	withHosts(t, "")
	usingTestRunner = true
	runner = failRunner{err: errors.New("boom")}
	t.Cleanup(func() {
		runner = execRunner{}
		usingTestRunner = false
	})
	p := Plan(nil, []string{"1.2.3.4"})
	p.UseHosts = false
	p.FlushDNS = false
	st, err := Apply(context.Background(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Failures) == 0 {
		t.Fatalf("expected failures, status %+v", st)
	}
	joined := strings.Join(st.Failures, "\n")
	if !strings.Contains(joined, "boom") && !strings.Contains(joined, "refused") {
		t.Fatalf("failures %v", st.Failures)
	}
}

func TestCommandsNotShelled(t *testing.T) {
	withHosts(t, "")
	rec := &recordRunner{}
	runner = rec
	usingTestRunner = true
	t.Cleanup(func() {
		runner = execRunner{}
		usingTestRunner = false
	})
	p := Plan(nil, []string{"89.127.233.127"})
	p.UseHosts = false
	p.FlushDNS = true
	_, _ = Apply(context.Background(), p, func(model.Progress) {})
	_, _ = Remove(context.Background(), nil)
	if len(rec.calls) == 0 {
		t.Fatal("expected firewall commands")
	}
	for _, c := range rec.calls {
		if strings.ContainsAny(c.name, " \t;&|") {
			t.Fatalf("shelled command name %q", c.name)
		}
		for _, a := range c.args {
			if strings.Contains(a, ";") || strings.Contains(a, "|") {
				t.Fatalf("args look shelled: %q %v", c.name, c.args)
			}
		}
	}
}

func TestApplyWithoutProgramPathsRunsNoProgramRules(t *testing.T) {
	withHosts(t, "")
	rec := &recordRunner{}
	runner = rec
	usingTestRunner = true
	t.Cleanup(func() {
		runner = execRunner{}
		usingTestRunner = false
	})
	p := Plan(nil, []string{"89.127.233.127"})
	p.UseHosts = false
	p.FlushDNS = false
	_, err := Apply(context.Background(), p, func(model.Progress) {})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.calls {
		joined := c.name + " " + strings.Join(c.args, " ")
		if strings.Contains(joined, "tbs_browser") {
			t.Fatalf("program rule ran without a resolved path: %s", joined)
		}
	}
	v := Verify(context.Background(), false)
	if len(v.ProgramNotes) != 0 || v.ProgramOK {
		t.Fatalf("program verify must be off unless expected: %+v", v)
	}
}

func TestApplyRefusesRealHostsInTests(t *testing.T) {
	hostsPathOverride = ""
	p := Plan(nil, nil)
	p.UseFirewall = false
	p.FlushDNS = false
	st, err := Apply(context.Background(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.HostsApplied {
		t.Fatal("must not write the real hosts file")
	}
	if len(st.Failures) == 0 {
		t.Fatal("expected a failure")
	}
}

func TestDefaultHostsPath(t *testing.T) {
	p := defaultHostsPath()
	if runtime.GOOS == "windows" {
		if !strings.Contains(strings.ToLower(p), `drivers\etc\hosts`) && !strings.Contains(strings.ToLower(p), `drivers/etc/hosts`) {
			t.Fatalf("windows hosts path %q", p)
		}
	} else if p != "/etc/hosts" {
		t.Fatalf("unix hosts path %q", p)
	}
}

func withHosts(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	hostsPathOverride = path
	t.Cleanup(func() { hostsPathOverride = "" })
	return path
}

type failRunner struct{ err error }

func (f failRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	return "", "nope", f.err
}

type recordRunner struct {
	calls []struct {
		name string
		args []string
	}
}

func (r *recordRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cp := append([]string(nil), args...)
	r.calls = append(r.calls, struct {
		name string
		args []string
	}{name, cp})
	return "Ok.\n", "", nil
}
