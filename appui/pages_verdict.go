package appui

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"github.com/owogametools/k2f-purge/internal/model"
)

func (a *App) verdictPage(c *ui.Context) {
	if a.Scan == nil {
		a.emptyState(c, tr("No scan yet", "尚未掃描", "未走査"), tr("Run a scan to produce a verdict.", "先跑掃描才有判定。", "走査すると判定が出ます。"), tr("Go to scan", "去掃描", "走査へ"), func() { a.Page = PageScan })
		return
	}

	confirmed, likely := 0, 0
	for _, f := range a.Scan.Findings {
		switch f.Confidence {
		case "confirmed":
			confirmed++
		case "likely":
			likely++
		}
	}

	ui.Column(c).Gap(18).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			micro(c, tr("Step 02 / Verdict", "步驟 02 / 判定", "手順 02 / 判定"), colAcid)
			display(c, a.Scan.Verdict, 86, verdictColor(a.Scan.Verdict))
			mono(c, a.verdictSentence(), 12, colMuted)
		})

		ui.Row(c).Gap(40).Children(func() {
			a.stat(c, fmt.Sprint(len(a.Scan.Findings)), tr("Findings", "發現", "検出"), colInk)
			a.stat(c, fmt.Sprint(confirmed), tr("Confirmed", "確認", "確定"), colDanger)
			a.stat(c, fmt.Sprint(likely), tr("Likely", "可能", "可能性"), colWarn)
			a.stat(c, fmt.Sprint(len(a.Scan.Targets)), tr("Targets", "目標", "対象"), colInk)
		})

		rule(c)

		if len(a.Scan.Findings) == 0 {
			p := panel(c)
			p.Children(func() {
				micro(c, tr("No listed indicator matched", "未命中已知指標", "既知指標に未一致"), colAcid)
				ui.Text(c, tr("That does not prove the machine is clean. It means none of the indicators from the public report were found, and only where the scanner could look.", "這不代表電腦乾淨。只代表公開報告的指標，在掃得到的地方都沒找到。", "清潔とは限りません。公開報告の指標が、走査できた範囲で見つからなかっただけです。")).
					FontSize(13).TextColor(colMuted)
			})
		} else {
			ui.Column(c).Gap(10).Children(func() {
				micro(c, trf("Evidence · %d", "證據 · %d", "証拠 · %d", len(a.Scan.Findings)), colDim)
				for _, f := range a.Scan.Findings {
					a.findingCard(c, f)
				}
			})
		}

		if len(a.Scan.Limitations) > 0 {
			p := panel(c)
			p.Children(func() {
				micro(c, tr("Limits of this scan", "本次限制", "今回の制限"), colWarn)
				for _, l := range a.Scan.Limitations {
					ui.Row(c).Gap(8).Children(func() {
						mono(c, "—", 10, colWarn)
						ui.Text(c, l).FontSize(12).TextColor(colMuted).Grow(1)
					})
				}
			})
		}

		ui.Row(c).Gap(10).Children(func() {
			a.actionButton(c, tr("Block indicators", "封鎖指標", "指標を遮断"), true, func() { a.Page = PageBlock })
			a.actionButton(c, tr("Isolate files", "隔離檔案", "ファイル隔離"), false, func() { a.Page = PageClean })
			a.ghostButton(c, tr("Exposure check", "曝險盤點", "露出確認"), func() { a.Page = PageExposure })
			a.ghostButton(c, tr("Report", "報告", "報告"), func() { a.Page = PageReport })
		})
	})
}

func (a *App) verdictSentence() string {
	switch a.Scan.Verdict {
	case "CONFIRMED":
		return tr("The agent ran on this machine. Assume every secret it could read was taken.", "這台機器跑過 agent。它能讀到的機密都當已外洩。", "エージェントはこの端末で動作しました。読めた機密はすべて持ち出された前提で扱ってください。")
	case "LIKELY":
		return tr("The malicious loader ran. No agent artefact was found, but that is not a clean bill.", "惡意 loader 執行過。沒找到 agent 殘留，但不代表乾淨。", "悪意ある loader が実行されました。agent の痕跡は未検出ですが、清潔とは言えません。")
	case "INCONCLUSIVE":
		return tr("The launcher data was not found. Nothing could be checked here.", "找不到啟動器資料。這裡查不了。", "ランチャー資料が見つかりません。ここでは確認できません。")
	default:
		return tr("None of the indicators in the public report matched on this machine.", "公開報告的指標，這台都沒命中。", "公開報告の指標は、この端末では一致しませんでした。")
	}
}

// zhOr says the Chinese copy when the ruleset carries one, and the English
// text otherwise, so a local overlay without translations still reads.
func zhOr(zh, en string) string {
	if strings.TrimSpace(zh) != "" {
		return zh
	}
	return en
}

// jaOr says the Japanese copy when the ruleset carries one, and the English
// text otherwise.
func jaOr(ja, en string) string {
	if strings.TrimSpace(ja) != "" {
		return ja
	}
	return en
}

func findingTitle(f model.Finding) string {
	return tr(f.Title, zhOr(f.TitleZH, f.Title), jaOr(f.TitleJA, f.Title))
}

func findingDetail(f model.Finding) string {
	return tr(f.Detail, zhOr(f.DetailZH, f.Detail), jaOr(f.DetailJA, f.Detail))
}

func (a *App) findingCard(c *ui.Context, f model.Finding) {
	p := ui.Column(c).FillWidth().Padding(16).Gap(8).
		Background(colSurface).Radius(10).Border(1, colLineSoft)
	p.Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			chip(c, strings.ToUpper(f.Confidence), severityColor(f.Severity))
			mono(c, f.RuleID, 10, colAcid)
			ui.Spacer(c)
			if !f.MTime.IsZero() {
				mono(c, f.MTime.Format("2006-01-02 15:04"), 9, colDim)
			}
		})
		ui.Text(c, findingTitle(f)).FontSize(15).TextColor(colInk)
		if d := findingDetail(f); d != "" {
			mono(c, clamp(d, 170), 10, colDim).SingleLine()
		}
		mono(c, clamp(f.Path, 130), 10, colMuted).SingleLine()
		if f.Snippet != "" {
			mono(c, clamp(f.Snippet, 150), 10, colDim).SingleLine()
		}
		if f.SHA256 != "" {
			mono(c, "sha256 "+f.SHA256, 9, colDim).SingleLine()
		}
	})
	if p.Hovered() {
		p.Background(colSurface2)
	}
}
