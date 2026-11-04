// Package appui builds the window: the app's state, the pages, and the
// native views and motion that show them.
package appui

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/owogametools/k2f-purge/internal/model"
	"github.com/owogametools/k2f-purge/internal/service"
)

// Page is one step of the response.
type Page int

const (
	PageScan Page = iota
	PageVerdict
	PageBlock
	PageClean
	PageExposure
	PageReport
)

var pageNames = [...]string{"Scan", "Verdict", "Block", "Clean", "Exposure", "Report"}

func (p Page) Name() string {
	if int(p) < len(pageNames) {
		return pageNames[p]
	}
	return ""
}

// App is the window's state. It lasts for the life of the window; the view
// reads it on the main thread and rebuilds the frame from it.
type App struct {
	Info model.AppInfo
	Svc  *service.Service
	Win  *mygo.Window

	Page Page
	Err  string
	Lang langPref

	LogScroll ui.ScrollState
	logSeen   int

	Busy      bool
	BusyLabel string
	Progress  model.Progress

	ScanOpts     model.ScanOptions
	ScanLog      []string
	Scan         *model.ScanResult
	Targets      []model.ScanTarget
	FindingCount int

	BlockPlan model.BlockPlan
	Block     *model.BlockStatus
	Verify    *model.BlockVerify

	CleanPlan   *model.CleanPlan
	CleanSel    map[string]bool
	CleanMode   int // 0 quarantine, 1 delete
	Confirm     string
	CleanResult *model.CleanResult
	Quarantine  []model.QuarantineEntry
	ShowQuarant bool

	Exposure      *model.ExposureResult
	ExposureQuery string
	OnlyPresent   bool

	ReportPath string
	Started    time.Time
}

// New makes the app's state.
func New(info model.AppInfo, svc *service.Service) *App {
	return &App{
		Info:      info,
		Svc:       svc,
		Page:      PageScan,
		Lang:      currentLangPref(),
		CleanSel:  map[string]bool{},
		BlockPlan: svc.BlockPlan(),
		Started:   time.Now(),
		ScanOpts:  model.ScanOptions{MaxFileMB: 128},
	}
}

// Attach gives the app the window its view is shown in.
func (a *App) Attach(w *mygo.Window) { a.Win = w }

// View builds the window's interface from the state.
func (a *App) View(c *ui.Context) {
	applyTheme(c)
	a.shortcuts(c)

	ui.Column(c).Fill().Background(colBG).Draw(drawGrain).Children(func() {
		a.titleBar(c)
		ui.Row(c).Grow(1).FillWidth().Children(func() {
			a.rail(c)
			a.stage(c)
		})
		a.footer(c)
	})
}

func (a *App) shortcuts(c *ui.Context) {
	if c.Shortcut(0, ui.KeyS) && !a.Busy {
		a.startScan()
	}
	if c.Shortcut(0, ui.KeyB) && a.Scan != nil {
		a.Page = PageBlock
	}
	if c.Shortcut(0, ui.KeyC) && a.Scan != nil {
		a.Page = PageClean
	}
	if c.Shortcut(0, ui.KeyE) && a.Scan != nil {
		a.Page = PageExposure
	}
	if c.Shortcut(0, ui.KeyR) && a.Scan != nil {
		a.Page = PageReport
	}
}

func (a *App) watermark(c *ui.Context) {
	ui.Column(c).Absolute().Top(-18).Right(10).PassThrough().Gap(0).Children(func() {
		display(c, fmt.Sprintf("%02d", int(a.Page)+1), 280, ui.RGBA(255, 255, 255, 0.030))
		mono(c, upper(pageLabel(a.Page)), 11, ui.RGBA(255, 255, 255, 0.10)).
			LetterSpacing(7).Rotate(-90).Margin(0, 0, 0, 34)
	})
}

func (a *App) stage(c *ui.Context) {
	ui.Column(c).Grow(1).Fill().Children(func() {
		a.watermark(c)
		if a.Busy {
			ui.Row(c).Padding(24, 40).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Spinner(c)
				mono(c, upper(a.BusyLabel), 22, colAcid)
				if a.Progress.Total > 0 {
					mono(c, fmt.Sprintf("%d / %d", a.Progress.Done, a.Progress.Total), 22, colMuted)
				}
				if a.Progress.Current != "" {
					mono(c, clamp(a.Progress.Current, 72), 22, colMuted)
				}
				ui.Spacer(c)
				a.ghostButton(c, tr("Cancel", "取消", "中止"), a.Svc.Cancel)
			})
			ui.Divider(c)
		}
		if a.Err != "" {
			ui.Row(c).Padding(20, 40).Gap(12).AlignItems(ui.Center).Background(ui.RGBA(255, 59, 31, 0.08)).Children(func() {
				mono(c, tr("ERROR", "錯誤", "ERROR"), 22, colDanger)
				ui.Text(c, a.Err).FontSize(26).TextColor(colInk).Grow(1)
				a.ghostButton(c, tr("Dismiss", "關閉", "閉じる"), func() { a.Err = "" })
			})
		}
		ui.Scroll(c).Grow(1).Fill().Children(func() {
			ui.Column(c).Padding(40, 52).Gap(32).Children(func() {
				switch a.Page {
				case PageScan:
					a.scanPage(c)
				case PageVerdict:
					a.verdictPage(c)
				case PageBlock:
					a.blockPage(c)
				case PageClean:
					a.cleanPage(c)
				case PageExposure:
					a.exposurePage(c)
				case PageReport:
					a.reportPage(c)
				}
			})
		})
	})
}

// ---------------------------------------------------------------------------
// background work

func (a *App) onMain(fn func()) {
	if a.Win == nil {
		return
	}
	a.Win.Update(fn)
}

func (a *App) startScan() {
	if a.Busy || a.Win == nil {
		return
	}
	a.Busy = true
	a.BusyLabel = tr("Scanning", "掃描中", "走査中")
	a.Err = ""
	a.ScanLog = nil
	a.logSeen = 0
	a.LogScroll.Y = math.MaxFloat32
	a.Scan = nil
	a.Targets = nil
	a.FindingCount = 0
	a.Page = PageScan
	a.Progress = model.Progress{}

	go func() {
		res, err := a.Svc.Scan(a.ScanOpts, func(ev model.ScanEvent) {
			a.onMain(func() { a.applyScanEvent(ev) })
		})
		a.onMain(func() {
			a.Busy = false
			if err != nil {
				a.Err = err.Error()
				return
			}
			a.Scan = res
			a.Page = PageVerdict
		})
	}()
}

func (a *App) applyScanEvent(ev model.ScanEvent) {
	switch ev.Type {
	case "target":
		if ev.Target != nil {
			a.Targets = append(a.Targets, *ev.Target)
			a.ScanLog = appendLog(a.ScanLog, "target  "+ev.Target.Kind+"  "+ev.Target.Path)
		}
	case "finding":
		if ev.Finding != nil {
			a.FindingCount++
			a.ScanLog = appendLog(a.ScanLog, "HIT     "+ev.Finding.RuleID+"  "+ev.Finding.Path)
		}
	case "progress":
		if ev.Progress != nil {
			a.Progress = *ev.Progress
		}
	case "log":
		a.ScanLog = appendLog(a.ScanLog, ev.Line)
	case "error":
		a.ScanLog = appendLog(a.ScanLog, "ERROR   "+ev.Err)
	}
}

func appendLog(lines []string, line string) []string {
	if strings.TrimSpace(line) == "" {
		return lines
	}
	lines = append(lines, clamp(line, 200))
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	return lines
}

func (a *App) startBlock(remove bool) {
	if a.Busy || a.Win == nil {
		return
	}
	a.Busy = true
	a.Err = ""
	a.BusyLabel = tr("Blocking", "封鎖中", "遮断中")
	if remove {
		a.BusyLabel = tr("Unblocking", "解除中", "解除中")
	}
	go func() {
		emit := func(p model.Progress) { a.onMain(func() { a.Progress = p }) }
		var (
			st  *model.BlockStatus
			err error
		)
		if remove {
			st, err = a.Svc.BlockRemove(emit)
		} else {
			st, err = a.Svc.BlockApply(a.BlockPlan, emit)
		}
		a.onMain(func() {
			a.Busy = false
			a.Progress = model.Progress{}
			if err != nil {
				a.Err = err.Error()
			}
			a.Block = st
			v := a.Svc.BlockVerify()
			a.Verify = &v
		})
	}()
}

func (a *App) startClean() {
	if a.Busy || a.Win == nil || a.CleanPlan == nil {
		return
	}
	mode := model.CleanQuarantine
	if a.CleanMode == 1 {
		if !strings.EqualFold(strings.TrimSpace(a.Confirm), "PURGE") {
			a.Err = tr("Type PURGE to confirm permanent deletion.", "輸入 PURGE 以確認永久刪除。", "PURGE と入力して完全削除を確定してください。")
			return
		}
		mode = model.CleanDelete
	}
	ids := make([]string, 0, len(a.CleanSel))
	for id, on := range a.CleanSel {
		if on {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		a.Err = tr("Select at least one item.", "至少選一項。", "少なくとも1件選んでください。")
		return
	}
	a.Busy = true
	a.Err = ""
	a.BusyLabel = tr("Quarantining", "隔離中", "隔離中")
	if mode == model.CleanDelete {
		a.BusyLabel = tr("Deleting", "刪除中", "削除中")
	}
	go func() {
		res, err := a.Svc.CleanApply(a.CleanPlan, ids, mode, func(p model.Progress) {
			a.onMain(func() { a.Progress = p })
		})
		a.onMain(func() {
			a.Busy = false
			a.Progress = model.Progress{}
			if err != nil {
				a.Err = err.Error()
			}
			a.CleanResult = res
			a.CleanSel = map[string]bool{}
			if entries, e := a.Svc.QuarantineList(); e == nil {
				a.Quarantine = entries
			}
		})
	}()
}

func (a *App) startExposure() {
	if a.Busy || a.Win == nil {
		return
	}
	a.Busy = true
	a.BusyLabel = tr("Checking exposure", "盤點中", "確認中")
	a.Err = ""
	go func() {
		res, err := a.Svc.ExposureScan(model.ExposureOptions{IncludeWine: true}, func(p model.Progress) {
			a.onMain(func() { a.Progress = p })
		})
		a.onMain(func() {
			a.Busy = false
			a.Progress = model.Progress{}
			if err != nil {
				a.Err = err.Error()
				return
			}
			a.Exposure = res
		})
	}()
}

func (a *App) saveReport() {
	if a.Win == nil {
		return
	}
	path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
		Parent:      a.Win,
		DefaultPath: "scan-report.md",
	})
	if err != nil || path == "" {
		return
	}
	saved, err := a.Svc.SaveReport(filepath.Dir(path))
	a.onMain(func() {
		if err != nil {
			a.Err = err.Error()
			return
		}
		a.ReportPath = saved
	})
}

func (a *App) saveExposure() {
	if a.Win == nil {
		return
	}
	path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
		Parent:      a.Win,
		DefaultPath: "rotation-checklist.md",
	})
	if err != nil || path == "" {
		return
	}
	md := a.Svc.ExposureMarkdown()
	if md == "" {
		a.Err = tr("run the exposure check first", "請先做曝險盤點", "先に露出確認をしてください")
		return
	}
	if err := os.WriteFile(path, []byte(md), 0o600); err != nil {
		a.Err = err.Error()
		return
	}
	a.ReportPath = path
}

func (a *App) loadQuarantine() {
	entries, err := a.Svc.QuarantineList()
	a.onMain(func() {
		if err != nil {
			a.Err = err.Error()
			return
		}
		a.Quarantine = entries
		a.ShowQuarant = true
	})
}

func (a *App) restoreQuarantine() {
	ids := a.selectedQuarantine()
	if len(ids) == 0 {
		a.Err = tr("Select at least one quarantined item.", "至少選一項隔離檔。", "隔離ファイルを1件以上選んでください。")
		return
	}
	if err := a.Svc.QuarantineRestore(ids); err != nil {
		a.Err = err.Error()
		return
	}
	a.loadQuarantine()
}

func (a *App) purgeQuarantine() {
	ids := a.selectedQuarantine()
	if len(ids) == 0 {
		a.Err = tr("Select at least one quarantined item.", "至少選一項隔離檔。", "隔離ファイルを1件以上選んでください。")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(a.Confirm), "PURGE") {
		a.Err = tr("Type PURGE to confirm permanent deletion.", "輸入 PURGE 以確認永久刪除。", "PURGE と入力して完全削除を確定してください。")
		return
	}
	if err := a.Svc.QuarantinePurge(ids); err != nil {
		a.Err = err.Error()
		return
	}
	a.loadQuarantine()
}

// selectedQuarantine reuses CleanSel, keyed as "q:<entry id>", so the clean
// list and the quarantine list never share a selection.
func (a *App) selectedQuarantine() []string {
	ids := []string{}
	for _, e := range a.Quarantine {
		if a.CleanSel["q:"+e.ID] {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

func clamp(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n < 2 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
