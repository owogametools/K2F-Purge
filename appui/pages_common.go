package appui

import (
	"fmt"

	"github.com/egoist/mygo/ui"
)

func (a *App) emptyState(c *ui.Context, title, body, action string, fn func()) {
	ui.Column(c).Gap(14).Padding(28).Background(colSurface).Radius(12).Border(1, colLineSoft).Children(func() {
		if cjkUI() {
			ui.Text(c, title).FontSize(34).TextColor(colInk)
		} else {
			display(c, upper(title), 34, colInk)
		}
		ui.Text(c, body).FontSize(26).TextColor(colMuted)
		ui.Row(c).Gap(10).Children(func() {
			a.actionButton(c, action, true, fn)
		})
	})
}

func sizeFmt(n int64) string {
	if n <= 0 {
		return "—"
	}
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.1f GB", float64(n)/(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/(k*k))
	case n >= k:
		return fmt.Sprintf("%.0f KB", float64(n)/k)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func percent(part, total int) float32 {
	if total <= 0 {
		return 0
	}
	return float32(part) / float32(total) * 100
}
