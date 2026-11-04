package appui

import (
	"fmt"
	"math"

	"github.com/egoist/mygo/ui"
)

func (a *App) titleBar(c *ui.Context) {
	tb := c.TitleBar()
	h := float32(76)
	if tb.Height > h {
		h = tb.Height
	}

	bar := ui.Row(c).Height(h).FillWidth().
		Padding(0, 14, 0, 18).
		AlignItems(ui.Center).
		BorderWidth(0, 0, 1, 0).BorderColor(colLineSoft).
		DragWindow()
	bar.Children(func() {
		ui.Box(c).Size(12, 12).Radius(1).Background(colAcid)
		ui.Text(c, "K2F").Font(fontDisplay).FontSize(28).TextColor(colInk).Margin(0, 7, 0, 0)
		ui.Text(c, "PURGE").Font(fontDisplay).FontSize(28).TextColor(colAcid).LetterSpacing(0.5)
		mono(c, "v"+a.Info.Version, 20, colDim).Margin(0, 0, 0, 14)

		ui.Spacer(c)

		mono(c, fmt.Sprintf("%02d / %s", int(a.Page)+1, upper(pageLabel(a.Page))), 20, colMuted).
			LetterSpacing(1.2).Margin(0, 0, 0, 16)

		ui.Box(c).Width(1).Height(24).Background(colLine).Margin(0, 14)
		a.windowButton(c, "—", func() { a.Win.Minimize() })
		a.windowButton(c, "▢", func() { a.Win.Maximize() })
		a.windowButton(c, "✕", func() { a.Win.Close() })
	})
}

func (a *App) windowButton(c *ui.Context, glyph string, fn func()) {
	b := ui.ButtonBase(c).Size(56, 44).Radius(6).TextColor(colMuted).OnClick(fn)
	b.Children(func() {
		ui.Text(c, glyph).Font(fontMono).FontSize(22).TextColor(colMuted)
	})
	if b.Hovered() {
		b.Background(colSurface2).TextColor(colInk)
	}
}

func (a *App) rail(c *ui.Context) {
	ui.Column(c).Width(320).FillHeight().
		Padding(28, 24, 20, 28).
		Gap(2).
		BorderWidth(0, 1, 0, 0).BorderColor(colLineSoft).
		Children(func() {
			micro(c, tr("Response", "處置", "対応"), colDim).Margin(0, 0, 10, 0)

			for p := Page(0); p <= PageReport; p++ {
				a.railItem(c, p)
			}

			ui.Spacer(c)

			ui.Column(c).Gap(6).Margin(0, 0, 6, 0).Children(func() {
				ui.Box(c).Height(1).FillWidth().Background(colLineSoft).Margin(0, 0, 10, 0)
				micro(c, tr("Ruleset", "規則集", "規則"), colDim)
				mono(c, a.Info.RulesetVersion, 20, colMuted)
				micro(c, tr("Host", "主機", "ホスト"), colDim).Margin(6, 0, 0, 0)
				mono(c, a.Info.OS+"/"+a.Info.Arch, 20, colMuted)
				micro(c, tr("Language", "語言", "言語"), colDim).Margin(6, 0, 0, 0)
				a.langMenu(c)
			})
		})
}

// langMenu is the select under HOST. It keeps the K2F look instead of the
// theme's default widget.
func (a *App) langMenu(c *ui.Context) {
	sel := ui.SelectBase(c, &a.Lang)
	current := langPrefLabel(a.Lang)

	trig := sel.Trigger.Height(48).FillWidth().Padding(0, 12).
		Radius(6).Border(1, colLineSoft).Background(colSurface).Value(current)
	if trig.Hovered() {
		trig.Background(colSurface2)
	}
	trig.Children(func() {
		mono(c, current, 18, colMuted)
		ui.Spacer(c)
		mono(c, "▾", 18, colDim)
	})

	sel.Popup(func(p ui.Element) {
		p.Padding(4).Width(190).Background(colSurface).Radius(8).Border(1, colLineSoft)
		for _, pref := range []langPref{langPrefAuto, langPrefEN, langPrefZH, langPrefJA} {
			fg := colMuted
			if pref == a.Lang {
				fg = colInk
			}
			item := sel.Item(pref).Height(48).Padding(0, 12).Radius(5)
			if item.Highlighted() {
				item.Background(colSurface2)
			}
			item.Children(func() {
				mono(c, langPrefLabel(pref), 18, fg)
				ui.Spacer(c)
				if pref == a.Lang {
					ui.Box(c).Size(6, 6).Radius(3).Background(colAcid)
				}
			})
		}
	})

	if sel.Trigger.Changed() {
		if err := setLangPref(a.Lang); err != nil {
			a.Err = err.Error()
		}
	}
}

func (a *App) railItem(c *ui.Context, p Page) {
	locked := p != PageScan && a.Scan == nil
	active := a.Page == p
	fg := colMuted
	if active {
		fg = colAcid
	}
	if locked {
		fg = colDim
	}

	row := ui.Row(c).Height(56).FillWidth().Padding(0, 16, 0, 12).
		Radius(6).Gap(12).AlignItems(ui.Center)
	if active {
		row.Background(ui.RGBA(200, 255, 0, 0.06))
	}
	if !locked {
		row.OnClick(func() { a.Page = p })
	}
	row.Children(func() {
		mono(c, fmt.Sprintf("%02d", int(p)+1), 18, fg)
		ui.Text(c, upper(pageLabel(p))).Font(fontMono).FontSize(20).LetterSpacing(1.1).TextColor(fg)
		if active {
			ui.Spacer(c)
			ui.Box(c).Size(6, 6).Radius(3).Background(colAcid)
		}
	})
	if row.Hovered() && !locked && !active {
		row.Background(colSurface)
	}
}

func (a *App) footer(c *ui.Context) {
	ui.Row(c).Height(52).FillWidth().Padding(0, 18).
		AlignItems(ui.Center).Gap(14).
		BorderWidth(1, 0, 0, 0).BorderColor(colLineSoft).
		Children(func() {
			mono(c, "K2F PURGE", 18, colDim)
			mono(c, "·", 18, colDim)
			mono(c, tr("RULES ", "規則 ", "規則 ")+a.Info.RulesetVersion, 18, colDim)
			mono(c, "·", 18, colDim)
			mono(c, a.elevationLabel(), 18, a.elevationColor())
			ui.Spacer(c)
			mono(c, tr("NOT AN ANTIVIRUS · NO NETWORK", "非防毒軟體 · 不連網", "ウイルス対策ではありません · 通信なし"), 18, colDim)
		})
}

func (a *App) elevationLabel() string {
	switch a.Info.ElevationMode {
	case "elevated":
		return tr("ELEVATED", "已提權", "管理者")
	case "per-op":
		return tr("ADMIN ON DEMAND", "按需提權", "都度昇格")
	default:
		return tr("LIMITED RIGHTS", "權限不足", "権限不足")
	}
}

func (a *App) elevationColor() ui.Color {
	if a.Info.ElevationMode == "limited" {
		return colWarn
	}
	return colDim
}

// ---------------------------------------------------------------------------
// shared pieces

func panel(c *ui.Context) ui.Element {
	return ui.Column(c).FillWidth().Padding(28).Gap(18).
		Background(colSurface).Radius(12).Border(1, colLineSoft)
}

func (a *App) actionButton(c *ui.Context, label string, primary bool, fn func()) {
	bg, fg := colSurface2, colInk
	if primary {
		bg, fg = colAcid, colInkOnAcid
	}
	b := ui.ButtonBase(c).Height(72).Padding(0, 28).Radius(8).
		Background(bg).TextColor(fg).OnClick(fn)
	b.Children(func() {
		ui.Text(c, upper(label)).Font(fontMono).FontSize(20).LetterSpacing(1.2).TextColor(fg)
	})
	if b.Hovered() {
		b.AnimatePose(ui.Pose{Y: -1, Scale: 1.01}, ui.Snappy)
	}
}

func (a *App) ghostButton(c *ui.Context, label string, fn func()) {
	b := ui.ButtonBase(c).Height(60).Padding(0, 20).Radius(7).
		Border(1, colLine).TextColor(colMuted).OnClick(fn)
	b.Children(func() {
		ui.Text(c, upper(label)).Font(fontMono).FontSize(18).LetterSpacing(1).TextColor(colMuted)
	})
	if b.Hovered() {
		b.Background(colSurface).TextColor(colInk)
	}
}

func chip(c *ui.Context, text string, color ui.Color) {
	ui.Box(c).Padding(6, 14).Radius(999).
		Background(ui.RGBA(255, 255, 255, 0.05)).Border(1, ui.RGBA(255, 255, 255, 0.08)).
		Children(func() {
			mono(c, text, 18, color)
		})
}

func (a *App) stat(c *ui.Context, value, label string, color ui.Color) {
	ui.Column(c).Gap(4).Children(func() {
		display(c, value, 38, color)
		micro(c, label, colDim)
	})
}

func progressLine(c *ui.Context, done, total int) {
	pct := float32(0)
	if total > 0 {
		pct = float32(done) / float32(total) * 100
	}
	if pct > 100 {
		pct = 100
	}
	ui.Box(c).Height(4).FillWidth().Background(colLineSoft).Children(func() {
		ui.Box(c).Height(4).WidthPercent(pct).Background(colAcid)
	})
}

func rule(c *ui.Context) {
	ui.Box(c).Height(1).FillWidth().Background(colLineSoft)
}

func sectionHead(c *ui.Context, num, title, detail string) {
	ui.Row(c).AlignItems(ui.Baseline).Gap(12).Children(func() {
		micro(c, num, colAcid)
		ui.Text(c, title).FontSize(36).TextColor(colInk)
		ui.Spacer(c)
		if detail != "" {
			mono(c, detail, 20, colDim)
		}
	})
	rule(c)
}

func maxf(a, b float32) float32 { return float32(math.Max(float64(a), float64(b))) }
