package appui

import (
	"fmt"
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
	svc, err := service.New("K2F PURGE", "0.3.1", "windows", "amd64", "bee")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	empty := &App{Info: svc.Info(), Svc: svc, CleanSel: map[string]bool{}, Started: now, ScanOpts: model.ScanOptions{MaxFileMB: 128}}
	render(t, dir, "00-empty-scan", empty, PageScan)
	render(t, dir, "00b-empty-verdict", empty, PageVerdict)

	a := previewApp(t, svc, now)
	for i, name := range []string{"01-scan", "02-verdict", "03-block", "04-clean", "05-exposure", "06-report"} {
		render(t, dir, name, a, Page(i))
	}
	a.Secrets = nil
	a.AstrLink = nil
	a.Exposure.Secrets = nil
	a.Exposure.AstrLink = nil
	render(t, dir, "05b-exposure-no-secrets", a, PageExposure)
}

func previewApp(t *testing.T, svc *service.Service, now time.Time) *App {
	t.Helper()
	launcher := t.TempDir()
	if err := os.MkdirAll(filepath.Join(launcher, "intl_service"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(launcher, "intl_service", "tbs_browser.exe"), []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{
		Info:         svc.Info(),
		Svc:          svc,
		CleanSel:     map[string]bool{"q-1": true},
		Started:      now,
		ScanOpts:     model.ScanOptions{MaxFileMB: 128, ExtraLauncherDirs: []string{launcher}},
		Page:         PageScan,
		BlockPlan:    svc.BlockPlan(),
		FindingCount: 4,
		LauncherPath: launcher,
		TBSExe:       filepath.Join(launcher, "intl_service", "tbs_browser.exe"),
	}
	a.LauncherDraft = launcher
	a.BlockPlan.BlockTBSBrowser = true
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
	a.Targets = a.Scan.Targets
	for i := 0; i < 18; i++ {
		a.ScanLog = append(a.ScanLog, fmt.Sprintf(`target  launcher-data  C:\Users\bee\AppData\Roaming\nikke_launcher\tbs_cache\data_%02d`, i))
	}
	a.ScanLog = append(a.ScanLog,
		`HIT     log.k2f_chan  C:\Users\bee\AppData\Local\NIKKE\Launcher\intl_service\debug.log`,
		`ERROR   read C:\Users\bee\AppData\Local\Temp\locked: access denied`,
	)

	a.Block = &model.BlockStatus{
		HostsApplied: true,
		HostsPath:    `C:\Windows\System32\drivers\etc\hosts`,
		Rules: []model.FirewallRule{
			{Name: "K2F PURGE - Block 89.127.233.127", Installed: true},
			{Name: "K2F PURGE - Block 89.126.250.172", Installed: true},
			{Name: "K2F PURGE - Block tbs_browser.exe (out)", Detail: "program " + a.TBSExe, Installed: true},
			{Name: "K2F PURGE - Block tbs_browser.exe (in)", Detail: "program " + a.TBSExe, Installed: true},
		},
		Persisted: true,
		Verified:  true,
	}
	v := model.BlockVerify{HostsOK: true, HostsDetail: "5 names sinkholed", FirewallOK: true, ProgramOK: true, AllOK: true,
		ProgramNotes: []string{"K2F PURGE - Block tbs_browser.exe (out): present", "K2F PURGE - Block tbs_browser.exe (in): present"}}
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
	fakeKey := "sk" + "-" + "proj" + "-" + "Ab3x" + "Y9Ab" + "3xY9" + "Ab3x" + "Y9Ab"
	a.Secrets = &model.SecretResult{
		FilesScanned: 214, FilesSkipped: 23,
		StartedAt: now, FinishedAt: now,
		Findings: []model.SecretFinding{
			{Engine: "rule", RuleID: "openai-project", Provider: "OpenAI", Kind: "api-key", Severity: "critical", Confidence: "confirmed", Path: `C:\Users\bee\.zshrc`, Line: 42, Column: 18, Value: fakeKey, Masked: "sk-pro…Y9Ab", Fingerprint: "a1b2c3d4e5f6", Action: "Revoke this key.", ActionZH: "撤銷這把金鑰。", ActionJA: "このキーを失効させてください。"},
			{Engine: "rule", RuleID: "aws-access-key-id", Provider: "AWS", Kind: "access-key", Severity: "critical", Confidence: "confirmed", Path: `C:\Users\bee\.aws\credentials`, Line: 3, Column: 21, Value: "AKIA" + "AB3X" + "Y9AB" + "3XY9" + "AB3X", Masked: "AKIAAB…AB3X", Fingerprint: "f6e5d4c3b2a1", Action: "Rotate the credential.", ActionZH: "輪替憑證。", ActionJA: "認証情報をローテーションしてください。"},
			{Engine: "astrlink", RuleID: "astrlink.common_secret", Provider: "Generic secret", Kind: "secret", Severity: "high", Confidence: "likely", Path: `C:\Users\bee\.bash_history`, Line: 108, Column: 9, Value: "Zx9" + "_Qw" + "8Lp8" + "+Rt5/", Masked: "Zx9_Qw…Rt5/", Fingerprint: "0f1e2d3c4b5a", Score: 0.97, Action: "Rotate this credential.", ActionZH: "輪替這組憑證。", ActionJA: "この認証情報をローテーションしてください。"},
		},
	}
	a.Exposure.Secrets = a.Secrets
	modelOnly := *a.Secrets
	modelOnly.Findings = []model.SecretFinding{a.Secrets.Findings[2]}
	a.AstrLink = &modelOnly
	a.Exposure.AstrLink = &modelOnly
	a.ModelStatus = model.AstrLinkStatus{Available: true, Bytes: 38 << 20}
	a.SecretsQuery = ""
	return a
}

func render(t *testing.T, dir, name string, a *App, page Page) {
	t.Helper()
	a.Page = page
	tt := ui.NewTester(a.View, 1600, 1000)
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
