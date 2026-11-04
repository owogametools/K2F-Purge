package appui

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/owogametools/k2f-purge/internal/model"
)

func busyScanApp() *App {
	a := &App{
		Info:     model.AppInfo{Version: "0.1.0", OS: "windows", Arch: "amd64", RulesetVersion: "test"},
		CleanSel: map[string]bool{},
		ScanOpts: model.ScanOptions{MaxFileMB: 128},
	}
	for i := 0; i < 18; i++ {
		a.Targets = append(a.Targets, model.ScanTarget{Kind: fmt.Sprintf("kind-%02d", i), Path: fmt.Sprintf(`C:\tmp\%02d`, i), Exists: true})
	}
	for i := 0; i < 40; i++ {
		a.ScanLog = append(a.ScanLog, fmt.Sprintf(`target  kind  C:\tmp\%02d`, i))
	}
	return a
}

func TestScanLogScrollStaysBounded(t *testing.T) {
	a := busyScanApp()
	tt := ui.NewTester(a.View, 1340, 860)
	tt.Frame()
	tt.Frame()

	if a.LogScroll.MaxY <= 0 {
		t.Fatalf("evidence log did not overflow: MaxY=%v", a.LogScroll.MaxY)
	}
	if a.LogScroll.Y != a.LogScroll.MaxY {
		t.Fatalf("log should follow the end: Y=%v MaxY=%v", a.LogScroll.Y, a.LogScroll.MaxY)
	}
}

func TestScanLogHoldsWhenScrolledUp(t *testing.T) {
	a := busyScanApp()
	tt := ui.NewTester(a.View, 1340, 860)
	tt.Frame()
	tt.Frame()

	max := a.LogScroll.MaxY
	a.LogScroll.Y = 0
	tt.Frame()

	if a.LogScroll.Y != 0 {
		t.Fatalf("scrolled-up view moved to %v, want 0", a.LogScroll.Y)
	}
	if a.LogScroll.MaxY != max {
		t.Fatalf("MaxY changed from %v to %v", max, a.LogScroll.MaxY)
	}

	a.LogScroll.Y = math.MaxFloat32
	tt.Frame()
	if a.LogScroll.Y != a.LogScroll.MaxY {
		t.Fatalf("returning to the end: Y=%v MaxY=%v", a.LogScroll.Y, a.LogScroll.MaxY)
	}
}

// A wheel notch at the end must reach the log: the follow rule may not cancel
// the scroll the reader just started in the same frame.
func TestScanLogWheelUpFromEnd(t *testing.T) {
	a := busyScanApp()
	tt := ui.NewTester(a.View, 1340, 860)
	tt.Frame()
	tt.Frame()

	header, ok := tt.Find("LIVE EVIDENCE STREAM")
	if !ok {
		t.Fatal("no stream header")
	}
	x, y := header.X+50, header.Y+120
	tt.Move(x, y)
	tt.Wheel(x, y, 0, -100)
	tt.Advance(100 * time.Millisecond)

	if a.LogScroll.MaxY <= 0 {
		t.Fatalf("evidence log did not overflow: MaxY=%v", a.LogScroll.MaxY)
	}
	if a.LogScroll.Y >= a.LogScroll.MaxY {
		t.Fatalf("wheel up did not move the log: Y=%v MaxY=%v", a.LogScroll.Y, a.LogScroll.MaxY)
	}
	held := a.LogScroll.Y
	tt.Frame()
	if a.LogScroll.Y != held {
		t.Fatalf("scrolled-up view moved from %v to %v", held, a.LogScroll.Y)
	}

	tt.Wheel(x, y, 0, 4000)
	tt.Advance(time.Second)
	if a.LogScroll.Y != a.LogScroll.MaxY {
		t.Fatalf("wheel down to the end: Y=%v MaxY=%v", a.LogScroll.Y, a.LogScroll.MaxY)
	}
}

func TestScanLogFollowsWhenContentArrives(t *testing.T) {
	a := &App{
		Info:     model.AppInfo{Version: "0.1.0", OS: "windows", Arch: "amd64", RulesetVersion: "test"},
		CleanSel: map[string]bool{},
	}
	tt := ui.NewTester(a.View, 1340, 860)
	tt.Frame()
	if a.LogScroll.Y != 0 || a.LogScroll.MaxY != 0 {
		t.Fatalf("empty log: Y=%v MaxY=%v", a.LogScroll.Y, a.LogScroll.MaxY)
	}

	for i := 0; i < 40; i++ {
		a.ScanLog = append(a.ScanLog, fmt.Sprintf(`target  kind  C:\tmp\%02d`, i))
	}
	tt.Frame()
	if a.LogScroll.MaxY <= 0 {
		t.Fatalf("evidence log did not overflow: MaxY=%v", a.LogScroll.MaxY)
	}
	if a.LogScroll.Y != a.LogScroll.MaxY {
		t.Fatalf("log should follow the end: Y=%v MaxY=%v", a.LogScroll.Y, a.LogScroll.MaxY)
	}
}
