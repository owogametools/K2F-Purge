package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/owogametools/k2f-purge/internal/ioc"
	"github.com/owogametools/k2f-purge/internal/model"
)

func TestRun_CleanLauncher(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictClear {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	if hasRule(res.Findings, "log.k2f_chan") {
		t.Fatal("false positive on FETCH_LIST log")
	}
}

func TestRun_LoaderOnly(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	mustWrite(t, filepath.Join(p.AppData, "nikke_launcher", "tbs_cache", "Code Cache", "js", "dd65fa4d61079e7e_0"), "cache")
	mustWrite(t, filepath.Join(p.AppData, "nikke_launcher", "tbs_cache", "Cache", "data_0"), "https://insightjs.com/l.js?f=aegis")
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictLikely {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	if !hasRule(res.Findings, "cache.loader_key") {
		t.Fatalf("missing loader key: %s", findingIDs(res.Findings))
	}
	if !hasRule(res.Findings, "cache.loader_url") {
		t.Fatalf("missing loader url: %s", findingIDs(res.Findings))
	}
}

func TestRun_Agent(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	mustWrite(t, launcherLog(p), "k2f_chan registered\nagent started as worker-1\n")
	mustWrite(t, filepath.Join(p.AppData, "nikke_launcher", "tbs_cache", "Local Storage", "leveldb", "000003.log"), "k2f.agent.state=active\n")
	mustWrite(t, filepath.Join(p.UserProfile, "Games", "NIKKE", "Launcher", "log", "tinyget", "tinyget.1.log"), "GET analytics.insightjs.com/comm/assets/insight.bundle\n")
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictConfirmed {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	for _, id := range []string{"log.k2f_chan", "log.agent_started", "state.k2f_agent", "log.payload_fetch"} {
		if !hasRule(res.Findings, id) {
			t.Errorf("missing %s in %s", id, findingIDs(res.Findings))
		}
	}
}

func TestRun_ChromeHelper(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	hexdir := strings.Repeat("a", 64)
	dll := filepath.Join(p.LocalAppData, "Google", "Chrome", "User Data", "PlatformExperienceHelper", hexdir, "platform_experience_helper.dll")
	mustWrite(t, dll, "mz")
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictConfirmed {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	if !hasRule(res.Findings, "chrome.helper_dll") {
		t.Fatalf("missing helper dll: %s", findingIDs(res.Findings))
	}
	for _, f := range res.Findings {
		if strings.EqualFold(filepath.Base(f.Path), "PlatformExperienceHelper") {
			t.Fatal("parent helper folder flagged")
		}
	}
}

func TestRun_TempArtefacts(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	mustWrite(t, filepath.Join(p.Temp, "k2f-b"+"creds-1"), "x")
	mustWrite(t, filepath.Join(p.Temp, "k2f_screen_1.jpg"), "jpeg")
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictLikely {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	if !hasRule(res.Findings, "temp.k2f_files") {
		t.Fatalf("missing temp: %s", findingIDs(res.Findings))
	}
}

func TestRun_KnownHash(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	payload := []byte("fixture-hash-payload")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	mustWrite(t, filepath.Join(p.UserProfile, "Games", "NIKKE", "Launcher", "log", "tinyget", "tinyget.payload.log"), string(payload))
	rules, err := ioc.Load()
	if err != nil {
		t.Fatal(err)
	}
	rules.SHA256 = append(rules.SHA256, hexSum)
	res := mustRun(t, p, rules, model.ScanOptions{})
	if res.Verdict != model.VerdictConfirmed {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	if !hasRule(res.Findings, "hash.known_bad") {
		t.Fatalf("missing hash: %s", findingIDs(res.Findings))
	}
}

func TestRun_RegistryHook(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the registry reader is Windows-only")
	}
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	orig := registryQuery
	registryQuery = func(key string) (bool, error) {
		return strings.Contains(key, "E77CC89B"), nil
	}
	t.Cleanup(func() { registryQuery = orig })
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictConfirmed {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	if !hasRule(res.Findings, "reg.clsid_hkcu") {
		t.Fatalf("missing registry: %s", findingIDs(res.Findings))
	}
}

func TestRun_Inconclusive(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictInconclusive {
		t.Fatalf("verdict %s", res.Verdict)
	}
}

func TestRun_DoesNotWrite(t *testing.T) {
	root, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	mustWrite(t, filepath.Join(root, "hosts"), "127.0.0.1 localhost\n")
	before := snapshot(t, root)
	_ = mustRun(t, p, nil, model.ScanOptions{})
	after := snapshot(t, root)
	if len(after) != len(before) {
		t.Fatalf("file count %d -> %d", len(before), len(after))
	}
	for path, meta := range before {
		got, ok := after[path]
		if !ok {
			t.Fatalf("missing %s", path)
		}
		if got != meta {
			t.Fatalf("modified %s", path)
		}
	}
}

func TestRun_SkipLargeFile(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	big := strings.Repeat("x", 2000) + "k2f_chan registered\n"
	mustWrite(t, launcherLog(p), big)
	res := mustRun(t, p, nil, model.ScanOptions{MaxFileMB: 0})
	// MaxFileMB 0 becomes default 128, so this is still small. Use a tiny cap via direct scanFile.
	path := launcherLog(p)
	got := scanFile(path, []needle{{check: ioc.Check{ID: "log.k2f_chan"}, pat: []byte("k2f_chan registered")}}, false, 100)
	if !got.tooLarge {
		t.Fatal("expected skip")
	}
	_ = res
}

func TestRun_Cancel(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := RunWithPaths(ctx, p, nil, model.ScanOptions{}, nil)
	if err == nil {
		t.Fatal("expected cancel error")
	}
}

func TestRun_WineAgent(t *testing.T) {
	_, p := fixturePaths(t, "linux")
	pfx := filepath.Join(p.Home, ".wine")
	mustWrite(t, filepath.Join(pfx, "system.reg"), "WINE\n")
	if err := os.MkdirAll(filepath.Join(pfx, "drive_c"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(pfx, "drive_c", "users", "steamuser", "AppData", "Roaming", "nikke_launcher")
	mustWrite(t, filepath.Join(data, "tbs_cache", "Local Storage", "leveldb", "000001.log"), "k2f.agent.state\n")
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictConfirmed {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	if !hasRule(res.Findings, "state.k2f_agent") {
		t.Fatalf("missing state: %s", findingIDs(res.Findings))
	}
}

func TestRun_SnippetLimitAndEvents(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	mustWrite(t, launcherLog(p), strings.Repeat("A", 400)+"k2f_chan registered"+strings.Repeat("B", 400)+"\x00\x01")
	var events []model.ScanEvent
	res, err := RunWithPaths(context.Background(), p, nil, model.ScanOptions{}, func(ev model.ScanEvent) {
		events = append(events, ev)
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != model.VerdictConfirmed {
		t.Fatalf("verdict %s", res.Verdict)
	}
	var sawTarget, sawFinding, sawDone bool
	for _, ev := range events {
		switch ev.Type {
		case "target":
			sawTarget = true
		case "finding":
			sawFinding = true
			if ev.Finding != nil {
				n := 0
				for range ev.Finding.Snippet {
					n++
				}
				if n > maxSnippetRunes {
					t.Fatalf("snippet runes %d", n)
				}
				if strings.ContainsRune(ev.Finding.Snippet, 0) {
					t.Fatal("nul in snippet")
				}
			}
		case "done":
			sawDone = true
		}
	}
	if !sawTarget || !sawFinding || !sawDone {
		t.Fatalf("events target=%v finding=%v done=%v", sawTarget, sawFinding, sawDone)
	}
}

func TestRun_LeftoverAndETag(t *testing.T) {
	_, p := fixturePaths(t, "windows")
	writeCleanLauncher(t, p)
	mustWrite(t, filepath.Join(p.LocalAppData, "Google", "Chrome", "User Data", "PlatformExperienceHelper", "old-clsid.txt"), "clsid")
	mustWrite(t, filepath.Join(p.UserProfile, "Games", "NIKKE", "Launcher", "log", "tinyget", "tinyget.mem.log"), "ETag: 6ae78037-3214f\n")
	res := mustRun(t, p, nil, model.ScanOptions{})
	if res.Verdict != model.VerdictLikely {
		t.Fatalf("verdict %s findings=%s", res.Verdict, findingIDs(res.Findings))
	}
	if !hasRule(res.Findings, "chrome.helper_leftover") || !hasRule(res.Findings, "log.etag") {
		t.Fatalf("findings %s", findingIDs(res.Findings))
	}
}

func fixturePaths(t *testing.T, goos string) (string, Paths) {
	t.Helper()
	root := t.TempDir()
	p := Paths{
		AppData:      filepath.Join(root, "AppData"),
		LocalAppData: filepath.Join(root, "Local"),
		Home:         filepath.Join(root, "Home"),
		Temp:         filepath.Join(root, "Temp"),
		SystemRoot:   filepath.Join(root, "Windows"),
		UserProfile:  filepath.Join(root, "User"),
		GOOS:         goos,
	}
	for _, d := range []string{p.AppData, p.LocalAppData, p.Home, p.Temp, p.SystemRoot, p.UserProfile} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root, p
}

func writeCleanLauncher(t *testing.T, p Paths) {
	t.Helper()
	mustWrite(t, filepath.Join(p.AppData, "nikke_launcher", "tbs_cache", "Local Storage", "leveldb", "CURRENT"), "1\n")
	mustWrite(t, launcherLog(p), "FETCH_LIST suc success\nstartup already in progress\ncollect_cookies: false\n")
}

func launcherLog(p Paths) string {
	return filepath.Join(p.UserProfile, "Games", "NIKKE", "Launcher", "intl_service", "debug.log")
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRun(t *testing.T, p Paths, rules *ioc.Rules, opts model.ScanOptions) *model.ScanResult {
	t.Helper()
	res, err := RunWithPaths(context.Background(), p, rules, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	return res
}

func hasRule(findings []model.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func findingIDs(findings []model.Finding) string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return strings.Join(ids, ",")
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		sum, err := hashFile(path, st.Size()+1)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		out[rel] = sum + " " + st.ModTime().UTC().Format(time.RFC3339Nano)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
