package appui

import (
	_ "embed"
	"log"

	"github.com/egoist/mygo/ui"
)

//go:embed fonts/Anton-Regular.ttf
var antonTTF []byte

//go:embed fonts/JetBrainsMono-Regular.ttf
var jetbrainsTTF []byte

const (
	fontDisplay = "Anton"
	fontMono    = "JetBrains Mono"
)

func init() {
	if err := ui.RegisterFont(antonTTF, fontDisplay); err != nil {
		log.Printf("register display font: %v", err)
	}
	if err := ui.RegisterFont(jetbrainsTTF, fontMono); err != nil {
		log.Printf("register mono font: %v", err)
	}
}

var (
	colBG        = ui.Hex("#050505")
	colSurface   = ui.Hex("#0B0B0B")
	colSurface2  = ui.Hex("#111110")
	colLine      = ui.RGBA(255, 255, 255, 0.12)
	colLineSoft  = ui.RGBA(255, 255, 255, 0.07)
	colInk       = ui.Hex("#F2F2EE")
	colMuted     = ui.Hex("#8A8A80")
	colDim       = ui.Hex("#55554F")
	colAcid      = ui.Hex("#C8FF00")
	colDanger    = ui.Hex("#FF3B1F")
	colWarn      = ui.Hex("#FFB000")
	colInkOnAcid = ui.Hex("#050505")
)

func applyTheme(c *ui.Context) {
	t := ui.DarkTheme()
	t.Background = colBG
	t.Surface = colSurface
	t.SurfaceHover = colSurface2
	t.SurfacePressed = colSurface2
	t.Border = colLine
	t.Text = colInk
	t.TextMuted = colMuted
	t.Accent = colAcid
	t.AccentHover = colAcid
	t.AccentPressed = colAcid
	t.AccentText = colInkOnAcid
	t.Danger = colDanger
	t.Warning = colWarn
	t.Success = colAcid
	t.Selection = ui.RGBA(200, 255, 0, 0.28)
	t.Focus = colAcid
	t.Radius = 10
	// Spacing sizes check boxes, text inputs and segmented controls; it moves
	// with FontSize so those controls stay proportional to the 2x reading text.
	t.Spacing = 8
	t.FontSize = 28
	c.SetTheme(t)
}

// display is the oversized Anton face used for the wordmark and verdicts.
func display(c *ui.Context, s string, size float32, color ui.Color) ui.Element {
	return ui.Text(c, s).Font(fontDisplay).FontSize(size).TextColor(color)
}

// mono is the data face: paths, rule ids, counts, logs.
func mono(c *ui.Context, s string, size float32, color ui.Color) ui.Element {
	return ui.Text(c, s).Font(fontMono).FontSize(size).TextColor(color)
}

// micro is an all-caps mono label with tracking, used above sections.
func micro(c *ui.Context, s string, color ui.Color) ui.Element {
	return ui.Text(c, upper(s)).Font(fontMono).FontSize(20).LetterSpacing(1.6).TextColor(color)
}

func upper(s string) string {
	b := []byte(s)
	for i, r := range b {
		if r >= 'a' && r <= 'z' {
			b[i] = r - 32
		}
	}
	return string(b)
}

func severityColor(sev string) ui.Color {
	switch sev {
	case "critical":
		return colDanger
	case "high":
		return colWarn
	case "medium":
		return colInk
	default:
		return colMuted
	}
}

func verdictColor(v string) ui.Color {
	switch v {
	case "CONFIRMED":
		return colDanger
	case "LIKELY":
		return colWarn
	case "CLEAR_OF_LISTED_IOCS":
		return colAcid
	default:
		return colInk
	}
}
