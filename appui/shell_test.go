package appui

import (
	"testing"

	"github.com/egoist/mygo/ui"
)

// The rail's LANGUAGE block must stay inside the window at the minimum size,
// and the footer must not be pushed off it.
func TestRailLanguageMenuFitsMinimumWindow(t *testing.T) {
	t.Setenv("K2F_UI_LANG", "en")
	resetLangState()
	t.Cleanup(resetLangState)
	a := busyScanApp()
	tt := ui.NewTester(a.View, 1280, 860)
	tt.Frame()

	trigger, ok := tt.Find("Auto (system)")
	if !ok {
		t.Fatalf("language trigger missing; texts: %v", tt.Texts())
	}
	if trigger.Y+trigger.H > 860 {
		t.Fatalf("language trigger at %v is below the 860px window", trigger)
	}
	footer, ok := tt.Find("NOT AN ANTIVIRUS · NO NETWORK")
	if !ok {
		t.Fatal("footer missing")
	}
	if footer.Y+footer.H > 860 {
		t.Fatalf("footer at %v is below the 860px window", footer)
	}
}

func TestLanguageMenuSwitchesAndPersists(t *testing.T) {
	t.Setenv("K2F_UI_LANG", "en")
	old := prefsPathOverride
	prefsPathOverride = t.TempDir()
	t.Cleanup(func() { prefsPathOverride = old })
	resetLangState()
	t.Cleanup(resetLangState)

	a := busyScanApp()
	a.Lang = langPrefAuto
	tt := ui.NewTester(a.View, 1340, 860)
	tt.Frame()

	// The env hook pins the first frame so the trigger reads in English; a
	// choice made now still applies to the session and is stored.
	t.Setenv("K2F_UI_LANG", "")
	if err := tt.Click("Auto (system)"); err != nil {
		t.Fatalf("open menu: %v", err)
	}
	tt.Frame()
	for _, label := range []string{"EN", "繁體中文", "日本語"} {
		if !tt.HasText(label) {
			t.Fatalf("menu item %q missing; texts: %v", label, tt.Texts())
		}
	}
	if err := tt.Click("日本語"); err != nil {
		t.Fatalf("choose Japanese: %v", err)
	}
	tt.Frame()

	if a.Lang != langPrefJA {
		t.Fatalf("Lang=%v, want JA", a.Lang)
	}
	if got := pick3("en", "zh", "ja"); got != "ja" {
		t.Fatalf("page copy did not switch: %q", got)
	}
	if got := loadLangPref(); got != langPrefJA {
		t.Fatalf("stored %v, want JA", got)
	}
	if !tt.HasText("01 / 走査") {
		t.Fatalf("title bar did not switch; texts: %v", tt.Texts())
	}
	if !tt.HasText("通信なし") {
		t.Fatalf("footer did not switch; texts: %v", tt.Texts())
	}
}
