package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

func sample(t *testing.T) model.ReportData {
	t.Helper()
	now := time.Date(2026, 11, 4, 3, 0, 0, 0, time.UTC)
	return model.ReportData{
		App: model.AppInfo{
			Name: "K2F PURGE", Version: "0.1.0", OS: "windows", Arch: "amd64",
			User: "victim", Elevated: true, ElevationMode: "elevated",
			CanBlock: true, CanClean: true, RulesetVersion: "2026-11-04.1",
		},
		Scan: model.ScanResult{
			ID: "scan-1", Verdict: model.VerdictConfirmed, RulesetVer: "2026-11-04.1",
			StartedAt: now.Add(-time.Minute), FinishedAt: now,
			Targets: []model.ScanTarget{
				{ID: "launcher-data:x", Kind: model.TargetLauncherData, Path: `C:\Users\victim\AppData\Roaming\nikke_launcher`, Exists: true},
			},
			Findings: []model.Finding{
				{
					RuleID: "log.k2f_chan", Title: "Agent 通道已註冊", Detail: "debug.log",
					Severity: model.SeverityCritical, Confidence: model.ConfidenceConfirmed,
					Path: `C:\Games\NIKKE\Launcher\intl_service\debug.log`, Offset: 12,
					Snippet: "k2f_chan registered", SHA256: "abc", MTime: now,
				},
			},
			Limitations: []string{"example limitation"},
		},
		Block: &model.BlockStatus{
			HostsApplied: true, HostsPath: `C:\Windows\System32\drivers\etc\hosts`,
			Rules:     []model.FirewallRule{{Name: "K2F PURGE - Block 89.127.233.127", Installed: true}},
			Persisted: true, Verified: true,
		},
		BlockVerify: &model.BlockVerify{HostsOK: true, FirewallOK: true, AllOK: true, HostsDetail: "blocked"},
		Clean: &model.CleanResult{
			Quarantined: 1, QuarantineDir: `C:\Users\victim\AppData\Local\k2f\quarantine\1`,
			Actions: []model.Action{{At: now, Kind: "quarantine", Detail: "helper dll"}},
		},
		Exposure: &model.ExposureResult{
			StartedAt: now.Add(-time.Minute), FinishedAt: now,
			Categories: []model.ExposureCategory{{Name: "ssh", Total: 2, Present: 1}},
			Items: []model.ExposureItem{
				{ID: "ssh-config", Category: "ssh", Label: "SSH config", Path: `C:\Users\victim\.ssh\config`, Exists: true, Size: 10, Action: "rotate"},
			},
			Limitations: []string{"existence only"},
		},
		Actions: []model.Action{
			{At: now, Kind: "scan", Detail: "completed"},
		},
		GeneratedAt: now,
	}
}

func TestMarkdownSectionOrder(t *testing.T) {
	md := Markdown(sample(t))
	heads := []string{"## 摘要", "## 判定", "## 證據", "## 已執行動作", "## 曝險", "## 建議下一步", "## 限制"}
	last := -1
	for _, h := range heads {
		i := strings.Index(md, h)
		if i < 0 {
			t.Fatalf("missing section %s", h)
		}
		if i <= last {
			t.Fatalf("section order: %s at %d after %d", h, i, last)
		}
		last = i
	}
	for _, need := range []string{
		"K2F PURGE", "0.1.0", "windows", "2026-11-04.1",
		"CONFIRMED", "log.k2f_chan", "k2f_chan registered", "abc",
		`C:\Games\NIKKE\Launcher\intl_service\debug.log`,
		"不是防毒軟體", "example limitation",
	} {
		if !strings.Contains(md, need) {
			t.Errorf("missing %q", need)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	raw, err := JSON(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env["schema_version"] != float64(1) {
		t.Fatalf("schema %v", env["schema_version"])
	}
	if _, ok := env["generated_at"].(string); !ok {
		t.Fatal("generated_at")
	}
	app, _ := env["app"].(map[string]any)
	if app["ruleset_version"] != "2026-11-04.1" {
		t.Fatalf("app %+v", app)
	}
	scan, _ := env["scan"].(map[string]any)
	if scan["verdict"] != "CONFIRMED" {
		t.Fatalf("verdict %v", scan["verdict"])
	}
	findings, _ := scan["findings"].([]any)
	f0, _ := findings[0].(map[string]any)
	if f0["rule_id"] != "log.k2f_chan" || f0["sha256"] != "abc" {
		t.Fatalf("finding %+v", f0)
	}
	if _, ok := env["block"].(map[string]any); !ok {
		t.Fatal("block")
	}
	if _, ok := env["block_verify"].(map[string]any); !ok {
		t.Fatal("block_verify")
	}
	if _, ok := env["clean"].(map[string]any); !ok {
		t.Fatal("clean")
	}
	if _, ok := env["exposure"].(map[string]any); !ok {
		t.Fatal("exposure")
	}
	// Deterministic: remarshal equals
	raw2, err := JSON(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(raw2) {
		t.Fatal("json not deterministic")
	}
}

func TestJSONNilSlices(t *testing.T) {
	raw, err := JSON(model.ReportData{})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.SchemaVersion != 1 {
		t.Fatalf("schema %d", env.SchemaVersion)
	}
	if env.Scan.Findings == nil || env.Actions == nil {
		t.Fatal("nil slices")
	}
}

func TestSaveWritesTwoFiles(t *testing.T) {
	dir := t.TempDir()
	data := sample(t)
	mdPath, err := Save(dir, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mdPath); err != nil {
		t.Fatal(err)
	}
	jsPath := strings.TrimSuffix(mdPath, ".md") + ".json"
	if _, err := os.Stat(jsPath); err != nil {
		t.Fatal(err)
	}
	if filepath.Base(mdPath) != "scan-report-20261104T030000Z.md" {
		t.Fatalf("name %s", filepath.Base(mdPath))
	}
	body, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "## 摘要") {
		t.Fatal("md content")
	}
}

func TestSaveEmptyDir(t *testing.T) {
	if _, err := Save("", sample(t)); err == nil {
		t.Fatal("expected error")
	}
}
