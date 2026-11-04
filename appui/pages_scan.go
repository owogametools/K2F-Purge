package appui

import (
	"fmt"
	"math"
	"strings"

	"github.com/egoist/mygo/ui"
)

func coverage(c *ui.Context, num, title, detail string) {
	p := ui.Column(c).Grow(1).Padding(14).Gap(6).
		Background(colSurface).Radius(9).Border(1, colLineSoft)
	p.Children(func() {
		micro(c, num, colAcid)
		ui.Text(c, title).FontSize(13).TextColor(colInk)
		mono(c, detail, 9, colDim).SingleLine()
	})
}

func (a *App) scanPage(c *ui.Context) {
	// Follow the end of the stream when it grows, unless the reader scrolled
	// up. Only content changes may move the view: writing the offset on every
	// frame would cancel a wheel notch the reader just started.
	if n := len(a.ScanLog); n != a.logSeen {
		a.logSeen = n
		if n == 0 || a.LogScroll.Y >= a.LogScroll.MaxY {
			a.LogScroll.Y = math.MaxFloat32
		}
	}

	ui.Column(c).Gap(18).Children(func() {
		ui.Row(c).AlignItems(ui.End).Children(func() {
			ui.Column(c).Gap(2).Children(func() {
				micro(c, tr("Step 01 / Detection", "步驟 01 / 偵測", "手順 01 / 検出"), colAcid)
				display(c, "SCAN", 104, colInk)
			})
			ui.Spacer(c)
			a.stat(c, fmt.Sprint(len(a.Targets)), tr("Targets", "目標", "対象"), colInk)
			ui.Box(c).Width(28)
			a.stat(c, fmt.Sprint(a.Progress.Done), tr("Files read", "已讀檔", "読取済"), colInk)
			ui.Box(c).Width(28)
			hits := colInk
			if a.FindingCount > 0 {
				hits = colDanger
			}
			a.stat(c, fmt.Sprint(a.FindingCount), tr("Hits", "命中", "命中"), hits)
		})

		progressLine(c, a.Progress.Done, a.Progress.Total)

		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			if a.Scan == nil {
				a.actionButton(c, tr("Begin scan", "開始掃描", "走査開始"), true, a.startScan)
			} else {
				a.actionButton(c, tr("Scan again", "再掃一次", "再走査"), true, a.startScan)
				a.ghostButton(c, tr("Open verdict", "看判定", "判定を見る"), func() { a.Page = PageVerdict })
			}
			if a.Busy {
				a.ghostButton(c, tr("Cancel", "取消", "中止"), a.Svc.Cancel)
			}
			ui.Spacer(c)
			mono(c, tr("Read-only · nothing is changed", "只讀取，不改動任何檔案。", "読み取り専用・何も変更しません"), 10, colDim)
		})

		if a.Progress.Current != "" {
			mono(c, clamp(a.Progress.Current, 110), 10, colMuted)
		}

		if len(a.Targets) > 0 {
			ui.Column(c).Gap(8).Children(func() {
				micro(c, tr("Places checked", "已查位置", "確認箇所"), colDim)
				ui.Row(c).Gap(6).Wrap().Children(func() {
					for _, t := range a.Targets {
						color := colMuted
						if t.Exists {
							color = colInk
						}
						chip(c, t.Kind, color)
					}
				})
			})
		}

		p := panel(c).Height(272).Clip()
		p.Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				micro(c, tr("Live evidence stream", "即時證據流", "証拠ストリーム"), colDim)
				ui.Spacer(c)
				mono(c, trf("%d lines", "%d 行", "%d 行", len(a.ScanLog)), 9, colDim)
			})
			ui.Box(c).Height(1).FillWidth().Background(colLineSoft)
			ui.Scroll(c).Grow(1).TrackScroll(&a.LogScroll).Children(func() {
				ui.Column(c).Gap(3).Children(func() {
					start := 0
					if len(a.ScanLog) > 16 {
						start = len(a.ScanLog) - 16
					}
					if len(a.ScanLog) == 0 {
						mono(c, tr("waiting for the first pass…", "等待首輪結果…", "初回の結果を待っています…"), 10, colDim)
						return
					}
					for _, line := range a.ScanLog[start:] {
						color := colMuted
						switch {
						case strings.HasPrefix(line, "HIT"):
							color = colAcid
						case strings.HasPrefix(line, "ERROR"):
							color = colDanger
						case strings.HasPrefix(line, "target"):
							color = colDim
						}
						mono(c, line, 10, color).SingleLine()
					}
				})
			})
		})

		ui.Row(c).Gap(10).Children(func() {
			coverage(c, "01", tr("Launcher logs", "啟動器日誌", "起動ログ"), "debug.log · tinyget")
			coverage(c, "02", tr("V8 code cache", "V8 快取", "V8 キャッシュ"), "4 loader keys · insightjs")
			coverage(c, "03", tr("Local storage", "本機儲存", "ローカル保存"), "k2f.agent.state")
			coverage(c, "04", tr("Chrome helper", "Chrome 幫手", "Chrome 補助"), "64-hex DLL · HKCU CLSID")
		})

		ui.Text(c, tr("The scanner only reads. It never writes, uploads, or opens a credential file.", "掃描只讀取。不寫入、不上傳、不打開憑證檔。", "走査は読み取りのみです。書き込み・送信・資格情報の閲覧はしません。")).
			FontSize(12).TextColor(colDim)
	})
}
