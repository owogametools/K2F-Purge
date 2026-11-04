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
			mono(c, tr("If the agent ran, assume every secret below was readable. This list only checks whether the path exists.", "若 agent 曾執行，下列機密都可能被讀。只檢查路徑是否存在。", "エージェントが動いていれば、以下の機密は読まれた前提です。経路の有無だけ確認します。"), 24, colMuted)
		})

		if a.Exposure == nil {
			a.emptyState(c, tr("Not checked yet", "尚未盤點", "未確認"),
				tr("Read-only: the app checks existence and timestamps, never file contents. 290 paths from the public report.", "只讀：查存在與時間戳，不讀內容。公開報告 290 條路徑。", "読み取り専用：存在と時刻のみ確認し、中身は読みません。公開報告の 290 経路です。"),
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
