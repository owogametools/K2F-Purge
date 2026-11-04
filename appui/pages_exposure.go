package appui

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"github.com/owogametools/k2f-purge/internal/model"
)

// categoryZH keeps the exposure groups readable in Chinese. Item labels stay
// in English: they are the names of the tools and files themselves.
var categoryZH = map[string]string{
	"ssh":           "SSH 連線",
	"gpg":           "GPG 金鑰",
	"ai-tools":      "AI 工具",
	"cloud":         "雲端帳號",
	"dev-tools":     "開發工具",
	"shell-history": "Shell 歷史",
	"browsers":      "瀏覽器",
	"wallets":       "加密錢包",
	"projects":      "專案資料夾",
	"nikke":         "NIKKE",
	"system":        "系統",
}

var categoryJA = map[string]string{
	"ssh":           "SSH",
	"gpg":           "GPG",
	"ai-tools":      "AI",
	"cloud":         "クラウド",
	"dev-tools":     "開発",
	"shell-history": "履歴",
	"browsers":      "ブラウザ",
	"wallets":       "暗号",
	"projects":      "案件",
	"nikke":         "NIKKE",
	"system":        "システム",
}

func categoryLabel(name string) string {
	return pick3(name, categoryZH[name], categoryJA[name])
}

func (a *App) exposurePage(c *ui.Context) {
	ui.Column(c).Gap(18).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			micro(c, tr("Step 05 / Exposure", "步驟 05 / 曝險", "手順 05 / 露出"), colAcid)
			display(c, "EXPOSURE", 86, colInk)
			mono(c, tr("The path list only checks existence. A content scan is a separate, explicit action that reads those files.",
				"下方路徑清單只檢查存在。內容掃描是另一個需你明確啟動的動作，會讀取這些檔案。",
				"下の経路一覧は存在だけを確認します。内容スキャンは別の明示的な操作で、これらのファイルを読みます。"), 24, colMuted)
		})

		if a.Exposure == nil {
			a.emptyState(c, tr("Not checked yet", "尚未盤點", "未確認"),
				tr("The path check reads metadata only; no file is opened. Content scanning is a separate action. 290 paths from the public report.", "路徑盤點只讀中繼資料，不開啟檔案。內容掃描是另一個動作。公開報告 290 條路徑。", "経路確認はメタデータのみで、ファイルは開きません。内容スキャンは別の操作です。公開報告の 290 経路です。"),
				tr("Check exposure", "開始盤點", "露出確認"), a.startExposure)
			return
		}

		present := 0
		for _, it := range a.Exposure.Items {
			if it.Exists {
				present++
			}
		}

		ui.Row(c).Gap(40).Children(func() {
			a.stat(c, fmt.Sprint(present), tr("Present", "存在", "存在"), colDanger)
			a.stat(c, fmt.Sprint(len(a.Exposure.Items)-present), tr("Absent", "不在", "不在"), colMuted)
			a.stat(c, fmt.Sprint(len(a.Exposure.Categories)), tr("Groups", "分組", "分類"), colInk)
		})

		a.secretsPanel(c)

		ui.Column(c).Gap(6).Children(func() {
			for _, cat := range a.Exposure.Categories {
				ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
					ui.Column(c).Width(220).Children(func() {
						mono(c, categoryLabel(cat.Name), 20, colInk)
					})
					bar := ui.Box(c).Height(3).Grow(1).Background(colLineSoft)
					bar.Children(func() {
						color := colMuted
						if cat.Present > 0 {
							color = colWarn
						}
						ui.Box(c).Height(3).WidthPercent(percent(cat.Present, cat.Total)).Background(color)
					})
					mono(c, fmt.Sprintf("%d / %d", cat.Present, cat.Total), 18, colDim).Width(120)
				})
			}
		})

		rule(c)

		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			ui.TextInput(c, &a.ExposureQuery).Placeholder(tr("Filter by path, tool or category", "依路徑、工具或類別篩選", "経路・ツール・分類で絞込")).Grow(1).Label(tr("Filter exposure", "篩選曝險", "露出を絞込"))
			ui.Checkbox(c, &a.OnlyPresent, tr("Only present", "只看存在", "存在のみ")).Label(tr("Only present", "只看存在", "存在のみ"))
			a.ghostButton(c, tr("Export checklist", "匯出清單", "一覧を出力"), a.saveExposure)
			a.ghostButton(c, tr("Re-check", "再盤一次", "再確認"), a.startExposure)
		})

		q := strings.ToLower(strings.TrimSpace(a.ExposureQuery))
		shown := 0
		ui.Column(c).Gap(2).Children(func() {
			for _, it := range a.Exposure.Items {
				if a.OnlyPresent && !it.Exists {
					continue
				}
				if q != "" {
					hay := strings.ToLower(it.Label + " " + it.Path + " " + it.Category + " " + it.Action)
					if !strings.Contains(hay, q) {
						continue
					}
				}
				shown++
				a.exposureRow(c, it)
			}
		})
		if shown == 0 {
			mono(c, tr("No item matches the filter.", "沒有符合的項目。", "該当なし。"), 20, colDim)
		}
	})
}

func (a *App) exposureRow(c *ui.Context, it model.ExposureItem) {
	dot := colDim
	if it.Exists {
		dot = severityColor(it.Severity)
	}
	row := ui.Row(c).Gap(12).Padding(8, 12).Radius(6).AlignItems(ui.Center)
	row.Children(func() {
		ui.Box(c).Size(10, 10).Radius(5).Background(dot)
		mono(c, clamp(it.Label, 42), 20, colInk).Width(320).SingleLine()
		mono(c, clamp(it.Path, 96), 20, colMuted).Grow(1).SingleLine()
		mono(c, categoryLabel(it.Category), 18, colDim).Width(160)
		if it.Exists {
			mono(c, tr("PRESENT", "存在", "存在"), 18, dot)
		} else {
			mono(c, "—", 18, colDim)
		}
	})
	if row.Hovered() && it.Exists {
		row.Background(colSurface)
	}
}

func (a *App) secretsPanel(c *ui.Context) {
	p := panel(c)
	p.Children(func() {
		micro(c, tr("Leaked secrets", "洩漏的敏感資料", "漏洩した秘密情報"), colAcid)
		mono(c, tr(
			"Reads the files listed above. Local only; nothing is uploaded.",
			"讀取上面列出的檔案。全程本機，不上傳。",
			"上に並んだファイルを読みます。端末内のみ、送信しません。"), 20, colMuted)

		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			a.actionButton(c, tr("Scan contents", "掃描內容", "内容をスキャン"), true, a.startSecretScan)
			if a.Secrets != nil {
				mono(c, fmt.Sprintf(tr("%d files / %d findings", "%d 個檔案 / %d 筆", "%d ファイル / %d 件"),
					a.Secrets.FilesScanned, len(a.Secrets.Findings)), 20, colDim)
			}
		})

		rule(c)

		ui.Column(c).Gap(4).Children(func() {
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				a.ghostButton(c, tr("Show leaked content", "顯示洩漏內容", "漏洩内容を表示"), a.startAstrLinkScan)
				switch {
				case a.ModelStatus.Available:
					mono(c, tr("Model ready on disk.", "模型已在本機就緒。", "モデルは端末内にあります。"), 18, colAcid)
				case a.ModelStatus.Note != "":
					mono(c, clamp(a.ModelStatus.Note, 110), 18, colDim).SingleLine()
				default:
					mono(c, tr("Model not bundled with this build.", "此版本未附模型。", "このビルドにはモデルがありません。"), 18, colDim)
				}
			})
			mono(c, tr("Directly lists the exposed sensitive data.",
				"直接列出暴露的敏感資料。",
				"露出した機密情報を直接一覧します。"), 18, colMuted)
			if a.AstrLink != nil {
				modelFindings := a.AstrLink.Findings
				ui.Row(c).Gap(40).Children(func() {
					a.stat(c, fmt.Sprint(len(modelFindings)), tr("Model findings", "模型找到", "モデル検出"), colWarn)
					a.stat(c, fmt.Sprint(a.AstrLink.FilesScanned), tr("Files read", "讀取檔案", "読取ファイル"), colInk)
				})
				ui.Column(c).Gap(4).Children(func() {
					for _, f := range modelFindings {
						a.secretRow(c, f)
					}
				})
			}
		})

		if a.Secrets == nil {
			mono(c, tr("Not run yet. The check above only looked at paths.",
				"尚未執行。上面的盤點只看路徑。",
				"未実行。上の確認は経路だけを見ています。"), 20, colDim)
			return
		}

		critical, high := 0, 0
		for _, f := range a.Secrets.Findings {
			switch f.Severity {
			case "critical":
				critical++
			case "high":
				high++
			}
		}
		ui.Row(c).Gap(40).Children(func() {
			a.stat(c, fmt.Sprint(len(a.Secrets.Findings)), tr("Secrets", "敏感資料", "秘密情報"), colDanger)
			a.stat(c, fmt.Sprint(critical), tr("Critical", "極高", "重大"), colDanger)
			a.stat(c, fmt.Sprint(high), tr("High", "高", "高"), colWarn)
		})

		if len(a.Secrets.Findings) == 0 {
			mono(c, tr("No credential-shaped value was found.",
				"沒有找到像憑證的值。",
				"認証情報らしい値は見つかりませんでした。"), 20, colDim)
			return
		}

		ui.TextInput(c, &a.SecretsQuery).Placeholder(tr("Filter by provider, path or value", "依供應商、路徑或值篩選", "プロバイダー・経路・値で絞込")).Grow(1).Label(tr("Filter secrets", "篩選敏感資料", "秘密情報を絞込"))

		q := strings.ToLower(strings.TrimSpace(a.SecretsQuery))
		shown := 0
		ui.Column(c).Gap(4).Children(func() {
			for _, f := range a.Secrets.Findings {
				if q != "" {
					hay := strings.ToLower(f.Provider + " " + f.Kind + " " + f.Path + " " + f.Value)
					if !strings.Contains(hay, q) {
						continue
					}
				}
				shown++
				a.secretRow(c, f)
			}
		})
		if shown == 0 {
			mono(c, tr("No finding matches the filter.", "沒有符合的項目。", "該当なし。"), 20, colDim)
		}
	})
}

func (a *App) secretRow(c *ui.Context, f model.SecretFinding) {
	dot := severityColor(f.Severity)
	ui.Column(c).Gap(2).Padding(8, 12).Radius(6).Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Box(c).Size(10, 10).Radius(5).Background(dot)
			mono(c, clamp(f.Provider+" / "+f.Kind, 36), 18, colInk).Width(260).SingleLine()
			mono(c, clamp(f.Path+":"+fmt.Sprint(f.Line), 88), 18, colMuted).Grow(1).SingleLine()
			if f.Engine == "astrlink" {
				chip(c, "MODEL", colAcid)
			} else {
				chip(c, "RULE", colWarn)
			}
			mono(c, f.Severity, 18, dot).Width(90)
		})
		mono(c, f.Value, 18, colInk)
		if action := pick3(f.Action, f.ActionZH, f.ActionJA); action != "" {
			mono(c, action, 18, colDim)
		}
	})
}
