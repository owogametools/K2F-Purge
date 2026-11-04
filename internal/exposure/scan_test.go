package exposure

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestScanWithHomeLstatOnly(t *testing.T) {
	home := t.TempDir()
	secret := filepath.Join(home, ".ssh", "config")
	writeFile(t, secret, "this-must-not-be-read HOST secret.example")
	if err := os.Chmod(secret, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o600) })

	// Workers report progress concurrently; the collector is the test's state.
	var (
		mu       sync.Mutex
		progress []model.Progress
	)
	res, err := ScanWithHome(context.Background(), home, model.ExposureOptions{}, func(p model.Progress) {
		mu.Lock()
		progress = append(progress, p)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("ScanWithHome: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	it, ok := findItem(res.Items, "ssh-config")
	if !ok {
		t.Fatalf("ssh-config missing, have %d items", len(res.Items))
	}
	if !it.Exists {
		t.Fatalf("ssh-config not exists path=%s note=%s", it.Path, it.Note)
	}
	if it.Size == 0 {
		t.Fatalf("expected Lstat size, got 0")
	}
	if len(progress) == 0 {
		t.Fatal("no progress")
	}

	nikke := filepath.Join(home, "AppData", "Roaming", "nikke_launcher")
	if err := os.MkdirAll(nikke, 0o700); err != nil {
		t.Fatal(err)
	}
	res2, err := ScanWithHome(context.Background(), home, model.ExposureOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	foundNikke := false
	for _, item := range res2.Items {
		if strings.Contains(item.Path, "nikke_launcher") && item.Exists && !strings.Contains(item.Path, "hmt") {
			foundNikke = true
			if !strings.HasPrefix(strings.ToLower(filepath.ToSlash(item.Path)), strings.ToLower(filepath.ToSlash(home))) {
				t.Fatalf("path escaped home: %s", item.Path)
			}
		}
	}
	if !foundNikke {
		// %APPDATA% maps per OS: ~/.config on Linux, ~/Library/Application
		// Support on macOS. Try the other one before failing.
		alt := filepath.Join(home, ".config", "nikke_launcher")
		if runtime.GOOS == "darwin" {
			alt = filepath.Join(home, "Library", "Application Support", "nikke_launcher")
		}
		if err := os.MkdirAll(alt, 0o700); err != nil {
			t.Fatal(err)
		}
		res3, err := ScanWithHome(context.Background(), home, model.ExposureOptions{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range res3.Items {
			if strings.Contains(item.Path, "nikke_launcher") && item.Exists && !strings.Contains(item.Path, "hmt") {
				foundNikke = true
			}
		}
	}
	if !foundNikke {
		t.Fatal("expected nikke_launcher present under fixture home")
	}
}

func TestScanGlobAndMissingEnv(t *testing.T) {
	home := t.TempDir()
	certs := filepath.Join(home, ".certs")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		writeFile(t, filepath.Join(certs, "k"+itoa(i)+".pem"), "x")
	}
	res, err := ScanWithHome(context.Background(), home, model.ExposureOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var certHits int
	truncated := false
	for _, it := range res.Items {
		if strings.HasPrefix(it.ID, "certs") && it.Exists {
			certHits++
			if strings.Contains(it.Note, "truncated") {
				truncated = true
			}
		}
	}
	if certHits != globCap {
		t.Fatalf("certs hits %d want %d", certHits, globCap)
	}
	if !truncated {
		t.Fatal("expected truncated note on glob cap")
	}

	var missing bool
	for _, it := range res.Items {
		if it.ID == "claude-config-dir-claude-json" && strings.Contains(it.Note, "environment variable not set") {
			missing = true
		}
	}
	if !missing {
		t.Fatal("expected missing env note for $CLAUDE_CONFIG_DIR")
	}
}

func TestScanWinePrefix(t *testing.T) {
	home := t.TempDir()
	pfx := filepath.Join(home, "fake-pfx")
	user := filepath.Join(pfx, "drive_c", "users", "steamuser", "AppData", "Roaming", "nikke_launcher")
	if err := os.MkdirAll(user, 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := ScanWithHome(context.Background(), home, model.ExposureOptions{
		IncludeWine:   true,
		ExtraPrefixes: []string{pfx},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range res.Items {
		if it.Exists && strings.Contains(it.Path, "nikke_launcher") && strings.Contains(it.Path, "steamuser") {
			found = true
			if !strings.HasPrefix(it.ID, "wine-") {
				t.Errorf("wine item id %s", it.ID)
			}
		}
	}
	if !found {
		t.Fatal("expected wine nikke_launcher")
	}
}

func TestScanCancel(t *testing.T) {
	home := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanWithHome(ctx, home, model.ExposureOptions{}, nil)
	if err == nil {
		t.Fatal("expected cancel error")
	}
}

func TestExportMarkdown(t *testing.T) {
	md := ExportMarkdown(&model.ExposureResult{
		Items: []model.ExposureItem{
			{ID: "ssh-config", Category: "ssh", Label: "SSH config", Path: "/home/a/.ssh/config", Exists: true, Size: 12, Action: "rotate"},
			{ID: "aws", Category: "cloud", Label: "AWS", Path: "/home/a/.aws/credentials", Exists: false, Note: "environment variable not set", Action: "rotate"},
		},
		Categories: []model.ExposureCategory{
			{Name: "ssh", Total: 1, Present: 1},
			{Name: "cloud", Total: 1, Present: 0},
		},
		Limitations: []string{"existence only"},
	})
	for _, need := range []string{"# 曝險輪替清單", "## SSH / 遠端連線", "## 雲端帳號", "`/home/a/.ssh/config`", "existence only"} {
		if !strings.Contains(md, need) {
			t.Errorf("missing %q in\n%s", need, md)
		}
	}
	if strings.Contains(md, "HOST secret") {
		t.Fatal("export leaked file contents")
	}
}

func TestSummarize(t *testing.T) {
	cats := summarize([]model.ExposureItem{
		{Category: "ssh", Exists: true},
		{Category: "ssh", Exists: false},
		{Category: "cloud", Exists: true},
	})
	if len(cats) < 2 {
		t.Fatalf("cats %v", cats)
	}
	if cats[0].Name != "ssh" || cats[0].Total != 2 || cats[0].Present != 1 {
		t.Fatalf("ssh %+v", cats[0])
	}
}
