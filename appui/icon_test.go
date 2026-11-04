package appui

import (
	"image/png"
	"os"
	"testing"

	"github.com/egoist/mygo/ui"
)

// TestIcon renders the app icon when K2F_ICON_OUT is set. The icon is built
// from the same type and colors as the window, so the taskbar mark and the
// wordmark cannot drift apart.
func TestIcon(t *testing.T) {
	out := os.Getenv("K2F_ICON_OUT")
	if out == "" {
		t.Skip("set K2F_ICON_OUT to render the icon")
	}
	icon := func(c *ui.Context) {
		applyTheme(c)
		ui.Column(c).Fill().Background(colBG).
			Center().Gap(28).Children(func() {
			ui.Text(c, "K2F").Font(fontDisplay).FontSize(390).
				TextColor(colAcid).LetterSpacing(4)
			ui.Row(c).Gap(16).AlignItems(ui.Center).Children(func() {
				ui.Box(c).Size(9, 9).Radius(1).Background(colDanger)
				ui.Text(c, "PURGE").Font(fontMono).FontSize(42).
					TextColor(colInk).LetterSpacing(16)
			})
		})
	}
	tt := ui.NewTester(icon, 1024, 1024)
	tt.Frame()
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, tt.Image()); err != nil {
		t.Fatal(err)
	}
}
