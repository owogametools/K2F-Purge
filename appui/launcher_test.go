package appui

import (
	"image"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestValidateLauncherDir(t *testing.T) {
	dir := t.TempDir()
	got, err := validateLauncherDir("  " + dir + "  ")
	if err != nil {
		t.Fatalf("absolute dir: %v", err)
	}
	if got != filepath.Clean(dir) {
		t.Fatalf("cleaned path: got %q, want %q", got, filepath.Clean(dir))
	}

	if _, err := validateLauncherDir(""); err == nil {
		t.Fatal("empty path must fail")
	}
	if _, err := validateLauncherDir("relative/folder"); err == nil {
		t.Fatal("relative path must fail")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := validateLauncherDir(missing); err == nil {
		t.Fatal("missing path must fail")
	}
	file := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateLauncherDir(file); err == nil {
		t.Fatal("a file must fail")
	}
}

func TestBlockPageTBSOptionAndActionOrder(t *testing.T) {
	t.Setenv("K2F_UI_LANG", "en")
	resetLangState()
	t.Cleanup(resetLangState)

	a := &App{
		Info:      model.AppInfo{OS: "windows", Version: "test"},
		CleanSel:  map[string]bool{},
		Page:      PageBlock,
		BlockPlan: model.BlockPlan{BlockTBSBrowser: true},
	}
	tt := ui.NewTester(a.View, 1600, 1000)
	tt.Frame()

	if !tt.HasText("Block tbs_browser.exe network access") {
		t.Fatalf("tbs_browser option missing; texts: %v", tt.Texts())
	}
	if err := tt.Click("Block tbs_browser.exe network access"); err != nil {
		t.Fatalf("toggle option: %v", err)
	}
	tt.Frame()
	if a.BlockPlan.BlockTBSBrowser {
		t.Fatal("clicking the checkbox did not clear BlockTBSBrowser")
	}

	// The page is taller than the window; scroll to the bottom so the action
	// row is laid out on screen.
	a.StageScroll.Y = math.MaxFloat32
	tt.Frame()

	cont, ok := tt.Find("CONTINUE TO CLEANUP")
	if !ok {
		t.Fatalf("continue action missing; texts: %v", tt.Texts())
	}
	reverify, ok := tt.Find("RE-VERIFY")
	if !ok {
		t.Fatalf("re-verify action missing; texts: %v", tt.Texts())
	}
	if hasExactText(tt.Texts(), "VERIFY") {
		t.Fatal("old Verify label still rendered")
	}
	if cont.X >= reverify.X {
		t.Fatalf("Continue must be left of Re-verify: %v vs %v", cont, reverify)
	}
	if cont.Y+cont.H > 1000 || reverify.Y+reverify.H > 1000 {
		t.Fatalf("actions below the window: continue=%v reverify=%v", cont, reverify)
	}

	// Continue is the primary action: it sits on the accent-colored button,
	// while Re-verify is a ghost with a transparent background.
	img := tt.Image()
	if !nearAcid(img, cont.X-12, cont.Y+cont.H/2) {
		t.Fatalf("Continue is not drawn as the primary action at %v", cont)
	}
	if nearAcid(img, reverify.X-12, reverify.Y+reverify.H/2) {
		t.Fatalf("Re-verify is drawn as primary at %v", reverify)
	}
}

func TestBlockPageNonWindowsShowsNote(t *testing.T) {
	t.Setenv("K2F_UI_LANG", "en")
	resetLangState()
	t.Cleanup(resetLangState)

	a := &App{
		Info:     model.AppInfo{OS: "linux", Version: "test"},
		CleanSel: map[string]bool{},
		Page:     PageBlock,
	}
	tt := ui.NewTester(a.View, 1600, 1000)
	tt.Frame()
	if !tt.HasText("Blocking tbs_browser.exe is Windows only.") {
		t.Fatalf("Windows-only note missing; texts: %v", tt.Texts())
	}
	if tt.HasText("Block tbs_browser.exe network access") {
		t.Fatal("checkbox must not render off Windows")
	}
}

func TestVerdictLauncherPanelRendersEmptyAndWithScan(t *testing.T) {
	t.Setenv("K2F_UI_LANG", "en")
	resetLangState()
	t.Cleanup(resetLangState)

	dir := t.TempDir()
	a := &App{
		Info:          model.AppInfo{OS: "windows", Version: "test"},
		CleanSel:      map[string]bool{},
		Page:          PageVerdict,
		LauncherPath:  dir,
		LauncherDraft: dir,
	}
	tt := ui.NewTester(a.View, 1600, 1000)
	tt.Frame()
	if !tt.HasText("LAUNCHER LOCATION") {
		t.Fatalf("launcher panel missing on empty verdict; texts: %v", tt.Texts())
	}
	if !tt.HasText("NO SCAN YET") {
		t.Fatalf("empty verdict missing; texts: %v", tt.Texts())
	}
	if !tt.HasText("SAVE AND RESCAN") {
		t.Fatalf("save action missing; texts: %v", tt.Texts())
	}
	if !tt.HasText("CLEAR") {
		t.Fatalf("clear action missing; texts: %v", tt.Texts())
	}

	a.Scan = &model.ScanResult{Verdict: model.VerdictInconclusive, Limitations: []string{"launcher data not found"}}
	tt.Frame()
	if !tt.HasText("LAUNCHER LOCATION") {
		t.Fatalf("launcher panel missing with a scan; texts: %v", tt.Texts())
	}
}

func hasExactText(texts []string, want string) bool {
	for _, s := range texts {
		if s == want {
			return true
		}
	}
	return false
}

func nearAcid(img *image.RGBA, x, y float32) bool {
	if x < 0 || y < 0 || int(x) >= img.Bounds().Dx() || int(y) >= img.Bounds().Dy() {
		return false
	}
	r, g, b, _ := img.At(int(x), int(y)).RGBA()
	// colAcid is #C8FF00.
	return r>>8 > 180 && r>>8 < 220 && g>>8 > 240 && b>>8 < 40
}
