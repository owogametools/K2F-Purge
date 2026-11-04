package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

// fake builds a synthetic value with a real shape. Tests must never carry
// a real credential, so every fixture is assembled from short pieces.
func fake(prefix string, n int) string {
	const alphabet = "Ab3xY9"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[i%len(alphabet)]
	}
	return prefix + string(b)
}

var (
	fakeOpenAI = fake("sk"+"-"+"proj"+"-", 24)
	fakeAWS    = "AKIA" + strings.Repeat("AB", 8)
	fakePass   = fake("Zx9"+"_"+"Qw3"+"-", 16)
)

func item(path string) model.ExposureItem {
	return model.ExposureItem{Kind: "file", Path: path, Exists: true}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanFindsProviderKeys(t *testing.T) {
	home := t.TempDir()
	env := filepath.Join(home, "credentials")
	write(t, env, "first line\nOPENAI_API_KEY = "+fakeOpenAI+"\naws = "+fakeAWS+"\n")

	res, err := Scan(context.Background(), []model.ExposureItem{item(env)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(res.Findings), res.Findings)
	}
	var openai, aws bool
	for _, f := range res.Findings {
		if f.Value == fakeOpenAI {
			openai = true
			if f.Line != 2 {
				t.Errorf("openai line = %d, want 2", f.Line)
			}
			if f.Path != env {
				t.Errorf("path = %q", f.Path)
			}
			if f.Masked == f.Value {
				t.Error("value was not masked")
			}
			if f.Fingerprint == "" {
				t.Error("empty fingerprint")
			}
		}
		if f.Value == fakeAWS {
			aws = true
			if f.Line != 3 {
				t.Errorf("aws line = %d, want 3", f.Line)
			}
		}
	}
	if !openai || !aws {
		t.Fatalf("openai=%v aws=%v findings=%+v", openai, aws, res.Findings)
	}
}

func TestScanSkipsPlaceholders(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "settings")
	placeholder := fake("your"+"_"+"api"+"_"+"key"+"_", 18)
	write(t, path, "api_key = "+placeholder+"\npassword = "+strings.Repeat("a", 24))
	res, err := Scan(context.Background(), []model.ExposureItem{item(path)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("placeholder reported: %+v", res.Findings)
	}
}

func TestScanSkipsBinaryAndSymlink(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "blob")
	if err := os.WriteFile(bin, []byte(fakeOpenAI+"\x00tail"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "link")
	_ = os.Symlink(bin, link)

	res, err := Scan(context.Background(), []model.ExposureItem{item(bin), item(link)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings from binary/symlink: %+v", res.Findings)
	}
	if res.FilesSkipped == 0 {
		t.Fatal("expected skipped count")
	}
	if res.FilesScanned != 0 {
		t.Fatalf("scanned %d", res.FilesScanned)
	}
}

func TestScanSkipsOversize(t *testing.T) {
	home := t.TempDir()
	big := filepath.Join(home, "big.txt")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	res, err := Scan(context.Background(), []model.ExposureItem{item(big)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 0 || res.FilesSkipped != 1 {
		t.Fatalf("scanned=%d skipped=%d", res.FilesScanned, res.FilesSkipped)
	}
	if !contains(res.Limitations, "over") {
		t.Fatalf("limitations = %v", res.Limitations)
	}
}

func TestScanDedupesSameValueOnSameLine(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "history")
	write(t, path, "export K="+fakeOpenAI+" && echo "+fakeOpenAI+"\n")
	res, err := Scan(context.Background(), []model.ExposureItem{item(path)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
}

func TestScanCancels(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "file")
	write(t, path, strings.Repeat("nothing here\n", 100))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, []model.ExposureItem{item(path)}, nil); err == nil {
		t.Fatal("want context error")
	}
}

func TestCandidatePathsFilters(t *testing.T) {
	items := []model.ExposureItem{
		{Kind: "dir", Path: "C:\\x", Exists: true},
		{Kind: "registry", Path: "HKCU\\x", Exists: true},
		{Kind: "file", Path: "C:\\a", Exists: false},
		{Kind: "file", Path: "C:\\a", Exists: true},
		{Kind: "glob", Path: "C:\\a", Exists: true},
		{Kind: "env", Path: "C:\\b", Exists: true},
	}
	got := candidatePaths(items)
	if len(got) != 2 {
		t.Fatalf("paths = %v", got)
	}
}

func TestGenericSecretNeedsEntropy(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "conf")
	write(t, path, "password = "+strings.Repeat("ab", 8)+"\ntoken = "+fakePass+"\n")
	res, err := Scan(context.Background(), []model.ExposureItem{item(path)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Value != fakePass {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestScanFindsGenericSecretAndConnectionString(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "conf")
	write(t, path, "secret = "+fakePass+"\ndb=postgres://user:Zq7-Vv2Lm8@db.local/app\n")
	res, err := Scan(context.Background(), []model.ExposureItem{item(path)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var generic, conn bool
	for _, f := range res.Findings {
		switch f.Value {
		case fakePass:
			generic = f.RuleID == "generic-assignment"
		case "Zq7-Vv2Lm8":
			conn = f.RuleID == "connection-string"
		}
	}
	if !generic || !conn {
		t.Fatalf("generic=%v connection=%v findings=%+v", generic, conn, res.Findings)
	}
}

func contains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
