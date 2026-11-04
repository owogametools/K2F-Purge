package appui

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/owogametools/k2f-purge/internal/model"
	"github.com/owogametools/k2f-purge/internal/service"
)

// TestPreview renders every page to PNG when K2F_PREVIEW_DIR is set. It is
// a design aid, not part of the normal suite.
func TestPreview(t *testing.T) {
	dir := os.Getenv("K2F_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set K2F_PREVIEW_DIR to render previews")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	svc, err := service.New("K2F PURGE", "0.1.0", "windows", "amd64", "bee")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	empty := &App{Info: svc.Info(), Svc: svc, CleanSel: map[string]bool{}, Started: now, ScanOpts: model.ScanOptions{MaxFileMB: 128}}
	render(t, dir, "00-empty-scan", empty, PageScan)

	a := previewApp(t, svc, now)
	for i, name := range []string{"01-scan", "02-verdict", "03-block", "04-clean", "05-exposure", "06-report"} {
		render(t, dir, name, a, Page(i))
	}
}

func previewApp(t *testing.T, svc *service.Service, now time.Time) *App {
	t.Helper()
	a := &App{
		Info:         svc.Info(),
		Svc:          svc,
		CleanSel:     map[string]bool{"q-1": true},
		Started:      now,
		ScanOpts:     model.ScanOptions{MaxFileMB: 128},
		Page:         PageScan,
		BlockPlan:    svc.BlockPlan(),
		FindingCount: 4,
	}
	a.Scan = &model.ScanResult{
		Verdict:    model.VerdictConfirmed,
		RulesetVer: "2026-11-04.1",
		StartedAt:  now.Add(-42 * time.Second),
		FinishedAt: now,
		Findings: []model.Finding{
			{RuleID: "log.k2f_chan", Title: "Agent channel registered", Detail: "debug.log records k2f_chan registered; the Lua agent ran inside the launcher.", TitleZH: "代理通道已註冊", DetailZH: "debug.log 記錄 k2f_chan registered；Lua agent 已在啟動器內執行。", TitleJA: "エージェント経路を登録", DetailJA: "debug.log に k2f_chan registered の記録があります。Lua エージェントがランチャー内で動作しました。", Severity: "critical", Confidence: "confirmed",
				Path: `C:\Users\bee\AppData\Local\NIKKE\Launcher\intl_service\debug.log`, Snippet: `k2f_chan registered`, MTime: now},
			{RuleID: "state.k2f_agent", Title: "Agent state in launcher storage", Detail: "LevelDB contains k2f.agent / k2f.agent.state.", TitleZH: "本機儲存內有代理狀態", DetailZH: "LevelDB 含 k2f.agent / k2f.agent.state。", TitleJA: "ローカル保存のエージェント状態", DetailJA: "LevelDB に k2f.agent / k2f.agent.state があります。", Severity: "critical", Confidence: "confirmed",
				Path: `C:\Users\bee\AppData\Roaming\nikke_launcher\tbs_cache\Local Storage\leveldb\000003.log`, Snippet: `k2f.agent.state`, MTime: now},
			{RuleID: "chrome.helper_dll", Title: "Chrome persistence DLL", Detail: "A 64-hex PlatformExperienceHelper folder contains platform_experience_helper.dll.", TitleZH: "Chrome 助手 DLL 持久化", DetailZH: "64 碼十六進位 PlatformExperienceHelper 資料夾內有 platform_experience_helper.dll。", TitleJA: "Chrome 補助 DLL の永続化", DetailJA: "64 桁十六進の PlatformExperienceHelper フォルダに platform_experience_helper.dll があります。", Severity: "critical", Confidence: "confirmed",
				Path: `C:\Users\bee\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\4f1c…\platform_experience_helper.dll`, SHA256: "9f2c4d…a71e", MTime: now},
			{RuleID: "log.payload_fetch", Title: "Payload downloaded", Detail: "tinyget logs mention analytics.insightjs.com.", TitleZH: "已從攻擊者主機取得 payload", DetailZH: "tinyget 日誌提到 analytics.insightjs.com。", TitleJA: "攻撃者ホストから payload 取得", DetailJA: "tinyget ログに analytics.insightjs.com の記載があります。", Severity: "high", Confidence: "confirmed",
				Path: `C:\Users\bee\AppData\Local\NIKKE\Launcher\log\tinyget\tinyget.1759482.log`, Snippet: `https://analytics.insightjs.com/comm/assets/insight.bundle`, MTime: now},
		},
		Targets: []model.ScanTarget{
			{Kind: "launcher-data", Path: `C:\Users\bee\AppData\Roaming\nikke_launcher`, Exists: true},
			{Kind: "chrome-helper", Path: `C:\Users\bee\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper`, Exists: true},
			{Kind: "temp", Path: `C:\Users\bee\AppData\Local\Temp`, Exists: true},
		},
		Limitations: []string{"The launcher install folder was not found; only the data folder was checked."},
	}
	a.Block = &model.BlockStatus{
		HostsApplied: true,
		HostsPath:    `C:\Windows\System32\drivers\etc\hosts`,
		Rules: []model.FirewallRule{
			{Name: "K2F PURGE - Block 89.127.233.127", Installed: true},
			{Name: "K2F PURGE - Block 89.126.250.172", Installed: true},
		},
		Persisted: true,
		Verified:  true,
	}
	v := model.BlockVerify{HostsOK: true, HostsDetail: "5 names sinkholed", FirewallOK: true, AllOK: true}
	a.Verify = &v
	a.CleanPlan = &model.CleanPlan{ScanID: "scan-1", RequiresRestart: true, Items: []model.CleanItem{
		{ID: "chrome_helper", Kind: "chrome_helper", Path: `C:\Users\bee\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\4f1c…`, Reason: "PlatformExperienceHelper 64-hex payload", ReasonZH: "PlatformExperienceHelper 64 碼 payload", ReasonJA: "PlatformExperienceHelper 64 桁 payload", RuleID: "chrome.helper_dll", Size: 842_112},
		{ID: "registry_clsid", Kind: "registry_clsid", Path: `HKCU\Software\Classes\CLSID\{E77CC89B-…}`, Reason: "agent HKCU CLSID persistence", ReasonZH: "agent 的 HKCU CLSID 持久化", ReasonJA: "agent の HKCU CLSID 永続化", RuleID: "reg.clsid_hkcu"},
		{ID: "launcher_cache", Kind: "launcher_cache", Path: `C:\Users\bee\AppData\Roaming\nikke_launcher\tbs_cache`, Reason: "launcher tbs_cache (loader/agent state)", ReasonZH: "啟動器 tbs_cache（loader／agent 狀態）", ReasonJA: "ランチャー tbs_cache（loader／agent 状態）", RuleID: "state.k2f_agent", Size: 1_284_000_000},
	}}
	a.Quarantine = []model.QuarantineEntry{{ID: "q-1", OriginalPath: `C:\Users\bee\AppData\Local\…\platform_experience_helper.dll`, RuleID: "chrome.helper_dll", Size: 842_112, CreatedAt: now}}
	a.ShowQuarant = true
	a.Exposure = &model.ExposureResult{
		Items: []model.ExposureItem{
			{Label: "Claude credentials", Category: "ai-tools", Path: `C:\Users\bee\.claude\.credentials.json`, Kind: "file", Severity: "critical", Action: "Revoke the Claude session.", Exists: true, Size: 512},
			{Label: "GitHub CLI hosts", Category: "dev-tools", Path: `C:\Users\bee\AppData\Roaming\GitHub CLI\hosts.yml`, Kind: "file", Severity: "critical", Action: "Revoke the GitHub token.", Exists: true, Size: 220},
			{Label: "SSH keys", Category: "ssh", Path: `C:\Users\bee\.ssh`, Kind: "dir", Severity: "critical", Action: "Generate new keys.", Exists: true},
			{Label: "AWS credentials", Category: "cloud", Path: `C:\Users\bee\.aws\credentials`, Kind: "file", Severity: "critical", Action: "Rotate the access key.", Exists: false},
		},
		Categories: []model.ExposureCategory{
			{Name: "ai-tools", Total: 54, Present: 11},
			{Name: "cloud", Total: 90, Present: 4},
			{Name: "dev-tools", Total: 77, Present: 19},
			{Name: "ssh", Total: 10, Present: 2},
			{Name: "browsers", Total: 18, Present: 3},
		},
		StartedAt: now, FinishedAt: now,
	}
	return a
}

func render(t *testing.T, dir, name string, a *App, page Page) {
	t.Helper()
	a.Page = page
	tt := ui.NewTester(a.View, 1340, 860)
	tt.Frame()
	img := tt.Image()
	f, err := os.Create(filepath.Join(dir, name+".png"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}
