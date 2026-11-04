package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

// Markdown renders a Traditional Chinese incident scan report.
// Section order is fixed: 摘要, 判定, 證據, 已執行動作, 曝險, 建議下一步, 限制.
func Markdown(r model.ReportData) string {
	var b strings.Builder
	b.WriteString("# K2F PURGE 掃描報告\n\n")
	b.WriteString("本工具**不是防毒軟體**。它只檢查已知、已公開的 IOC 清單，不能證明系統安全。\n\n")

	writeSummary(&b, r)
	writeVerdict(&b, r)
	writeEvidence(&b, r)
	writeActions(&b, r)
	writeExposure(&b, r)
	writeNext(&b, r)
	writeLimits(&b, r)
	return b.String()
}

func writeSummary(b *strings.Builder, r model.ReportData) {
	b.WriteString("## 摘要\n\n")
	app := r.App
	fmt.Fprintf(b, "- 應用程式：%s %s\n", nz(app.Name, "K2F PURGE"), nz(app.Version, "unknown"))
	fmt.Fprintf(b, "- 作業系統：%s/%s\n", nz(app.OS, "unknown"), nz(app.Arch, "unknown"))
	fmt.Fprintf(b, "- 使用者：%s\n", nz(app.User, "unknown"))
	fmt.Fprintf(b, "- 權限：elevated=%v mode=%s can_block=%v can_clean=%v\n",
		app.Elevated, nz(app.ElevationMode, "unknown"), app.CanBlock, app.CanClean)
	fmt.Fprintf(b, "- 規則版本：%s\n", firstNonEmpty(r.Scan.RulesetVer, app.RulesetVersion, "unknown"))
	fmt.Fprintf(b, "- 報告產生時間：%s\n", fmtTime(r.GeneratedAt))
	fmt.Fprintf(b, "- 掃描識別碼：%s\n", nz(r.Scan.ID, "—"))
	fmt.Fprintf(b, "- 掃描時間：%s → %s\n", fmtTime(r.Scan.StartedAt), fmtTime(r.Scan.FinishedAt))
	fmt.Fprintf(b, "- 判定：%s\n", nz(r.Scan.Verdict, "UNKNOWN"))
	fmt.Fprintf(b, "- 發現數量：%d\n", len(r.Scan.Findings))
	fmt.Fprintf(b, "- 掃描目標：%d\n", len(r.Scan.Targets))
	if r.Exposure != nil {
		present := 0
		for _, c := range r.Exposure.Categories {
			present += c.Present
		}
		fmt.Fprintf(b, "- 曝險路徑（存在）：%d\n", present)
	}
	b.WriteByte('\n')
}

func writeVerdict(b *strings.Builder, r model.ReportData) {
	b.WriteString("## 判定\n\n")
	v := r.Scan.Verdict
	fmt.Fprintf(b, "**%s**\n\n", nz(v, "UNKNOWN"))
	switch v {
	case model.VerdictConfirmed:
		b.WriteString("至少一項**已確認**訊號命中：agent 確實在此機器上執行過。日誌無法告訴你攻擊者下了哪些指令，必須假設最壞情況。\n\n")
	case model.VerdictLikely:
		b.WriteString("未見 agent 落地的強訊號，但 loader 曾執行（快取鍵或 insightjs 字串）。攻擊鏈的第一階段已發生。\n\n")
	case model.VerdictInconclusive:
		b.WriteString("找不到可掃描的 launcher 資料，或資料已被刪除／輪替。**這不代表安全。**\n\n")
	case model.VerdictClear:
		b.WriteString("已完整掃描目前能找到的目標，**未命中本工具內建的 IOC 清單**。這只表示「報告列出的 IOC」沒有出現，不是「系統沒有惡意軟體」。\n\n")
	default:
		b.WriteString("判定值未設定或無法識別。\n\n")
	}
	if len(r.Scan.Targets) > 0 {
		b.WriteString("掃描目標：\n\n")
		for _, t := range r.Scan.Targets {
			mark := "absent"
			if t.Exists {
				mark = "present"
			}
			fmt.Fprintf(b, "- `%s` %s `%s` (%s)", t.Kind, mark, t.Path, t.ID)
			if t.Note != "" {
				fmt.Fprintf(b, " — %s", t.Note)
			}
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
}

func writeEvidence(b *strings.Builder, r model.ReportData) {
	b.WriteString("## 證據\n\n")
	if len(r.Scan.Findings) == 0 {
		b.WriteString("沒有命中任何內建規則。\n\n")
		return
	}
	for i, f := range r.Scan.Findings {
		fmt.Fprintf(b, "### %d. %s\n\n", i+1, firstNonEmpty(f.TitleZH, f.Title, f.RuleID))
		fmt.Fprintf(b, "- 規則：`%s`\n", nz(f.RuleID, "—"))
		fmt.Fprintf(b, "- 嚴重度 / 信心：%s / %s\n", nz(f.Severity, "—"), nz(f.Confidence, "—"))
		fmt.Fprintf(b, "- 路徑：`%s`\n", nz(f.Path, "—"))
		if f.Offset != 0 {
			fmt.Fprintf(b, "- 位移：%d\n", f.Offset)
		}
		if f.SHA256 != "" {
			fmt.Fprintf(b, "- SHA-256：`%s`\n", f.SHA256)
		}
		if !f.MTime.IsZero() {
			fmt.Fprintf(b, "- mtime：%s\n", fmtTime(f.MTime))
		}
		if d := firstNonEmpty(f.DetailZH, f.Detail); d != "" {
			fmt.Fprintf(b, "- 說明：%s\n", d)
		}
		if f.Snippet != "" {
			fmt.Fprintf(b, "- 片段：`%s`\n", f.Snippet)
		}
		b.WriteByte('\n')
	}
}

func writeActions(b *strings.Builder, r model.ReportData) {
	b.WriteString("## 已執行動作\n\n")
	wrote := false
	if r.Block != nil {
		wrote = true
		b.WriteString("### 封鎖\n\n")
		fmt.Fprintf(b, "- hosts 已套用：%v 路徑 `%s`\n", r.Block.HostsApplied, nz(r.Block.HostsPath, "—"))
		fmt.Fprintf(b, "- 已持久化：%v 已驗證：%v\n", r.Block.Persisted, r.Block.Verified)
		for _, rule := range r.Block.Rules {
			fmt.Fprintf(b, "- 防火牆：%s installed=%v %s\n", rule.Name, rule.Installed, rule.Detail)
		}
		for _, f := range r.Block.Failures {
			fmt.Fprintf(b, "- 失敗：%s\n", f)
		}
		for _, w := range r.Block.Warnings {
			fmt.Fprintf(b, "- 警告：%s\n", w)
		}
		b.WriteByte('\n')
	}
	if r.BlockVerify != nil {
		wrote = true
		b.WriteString("### 封鎖驗證\n\n")
		fmt.Fprintf(b, "- hosts：%v %s\n", r.BlockVerify.HostsOK, r.BlockVerify.HostsDetail)
		fmt.Fprintf(b, "- 防火牆：%v\n", r.BlockVerify.FirewallOK)
		for _, n := range r.BlockVerify.FirewallNotes {
			fmt.Fprintf(b, "- %s\n", n)
		}
		fmt.Fprintf(b, "- 全部通過：%v\n\n", r.BlockVerify.AllOK)
	}
	if r.Clean != nil {
		wrote = true
		b.WriteString("### 清理\n\n")
		fmt.Fprintf(b, "- 隔離：%d 刪除：%d 略過：%d\n", r.Clean.Quarantined, r.Clean.Deleted, r.Clean.Skipped)
		fmt.Fprintf(b, "- 需要重開機：%v 隔離區：`%s`\n", r.Clean.RequiresRestart, nz(r.Clean.QuarantineDir, "—"))
		for _, f := range r.Clean.Failures {
			fmt.Fprintf(b, "- 失敗：%s\n", f)
		}
		for _, a := range r.Clean.Actions {
			fmt.Fprintf(b, "- %s %s %s\n", fmtTime(a.At), a.Kind, a.Detail)
		}
		b.WriteByte('\n')
	}
	if len(r.Actions) > 0 {
		wrote = true
		b.WriteString("### 時間線\n\n")
		for _, a := range r.Actions {
			fmt.Fprintf(b, "- %s `%s` %s\n", fmtTime(a.At), a.Kind, a.Detail)
		}
		b.WriteByte('\n')
	}
	if !wrote {
		b.WriteString("尚未執行封鎖或清理。\n\n")
	}
}

func writeExposure(b *strings.Builder, r model.ReportData) {
	b.WriteString("## 曝險\n\n")
	if r.Exposure == nil {
		b.WriteString("未執行曝險盤點。\n\n")
		return
	}
	if len(r.Exposure.Categories) > 0 {
		b.WriteString("分類統計：\n\n")
		for _, c := range r.Exposure.Categories {
			fmt.Fprintf(b, "- %s：存在 %d / %d\n", c.Name, c.Present, c.Total)
		}
		b.WriteByte('\n')
	}
	present := 0
	for _, it := range r.Exposure.Items {
		if !it.Exists {
			continue
		}
		present++
		fmt.Fprintf(b, "- [%s] `%s` %s\n", it.Category, it.Path, it.Label)
		if it.Action != "" {
			fmt.Fprintf(b, "  建議：%s\n", it.Action)
		}
	}
	if present == 0 {
		b.WriteString("沒有偵測到存在的曝險路徑（或尚未掃描到）。\n")
	}
	b.WriteByte('\n')
}

func writeNext(b *strings.Builder, r model.ReportData) {
	b.WriteString("## 建議下一步\n\n")
	b.WriteString("1. 在 Level Infinite 確認修復並清除 `tbs_cache` 之前，不要開啟 NIKKE PC launcher。\n")
	b.WriteString("2. 封鎖 `insightjs.com`、`analytics.insightjs.com`、`insightjs.org` 與 IP `89.127.233.127`、`89.126.250.172`。\n")
	switch r.Scan.Verdict {
	case model.VerdictConfirmed, model.VerdictLikely:
		b.WriteString("3. 依清理計畫隔離惡意落地物；Windows 請只刪 HKCU 的惡意 CLSID，**不要動 HKLM**。\n")
		b.WriteString("4. 從乾淨裝置輪替密碼與 token：NIKKE／Level Infinite、電子郵件、Discord、瀏覽器已存密碼、SSH、雲端金鑰、AI 工具。\n")
		b.WriteString("5. 登出所有工作階段（cookie 可在沒有密碼的情況下使用）。加密錢包請移到新種子。\n")
		b.WriteString("6. 日誌無法顯示攻擊者執行過哪些指令，請假設憑證與文件都已外洩。\n")
	default:
		b.WriteString("3. 即使本次未命中內建 IOC，若曾在 2026-09-27 之後開啟 launcher，仍建議輪替重要憑證。\n")
		b.WriteString("4. 若 launcher 資料夾已被刪除，判定可能是 INCONCLUSIVE：補上安裝路徑後再掃一次。\n")
	}
	b.WriteString("最後：本工具不連網、不讀取憑證內容、不代為撤銷 token。輪替必須由你在官方網站完成。\n\n")
}

func writeLimits(b *strings.Builder, r model.ReportData) {
	b.WriteString("## 限制\n\n")
	b.WriteString("- 只確認「報告列出的 IOC」，不是通用惡意軟體掃描。\n")
	b.WriteString("- 不讀取憑證或錢包內容，不連網，不上傳報告。\n")
	b.WriteString("- `FETCH_LIST suc success` 是正常日誌；`PlatformExperienceHelper` 父資料夾是 Chrome 正常建立的。\n")
	b.WriteString("- HKLM 同名 CLSID 指向 `wpc.dll`，是正常系統元件。\n")
	seen := map[string]struct{}{}
	writeLim := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		fmt.Fprintf(b, "- %s\n", s)
	}
	for _, s := range r.Scan.Limitations {
		writeLim(s)
	}
	if r.Exposure != nil {
		for _, s := range r.Exposure.Limitations {
			writeLim(s)
		}
	}
	b.WriteByte('\n')
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}

func nz(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
