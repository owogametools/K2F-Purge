// Package appui builds the window: the app's state, the pages, and the
// native views and motion that show them.
package appui

import (
	"context"
	"errors"
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
	// Notice is a neutral outcome, such as a cancelled scan. It is not an
	// error and is cleared when the next action starts.
	Notice string
	Lang   langPref

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

	LauncherPath  string // saved and validated, also in ScanOpts.ExtraLauncherDirs
	LauncherDraft string // text field binding
	LauncherErr   string // inline validation message
	TBSExe        string // last resolved tbs_browser.exe, display cache

	StageScroll ui.ScrollState // the page body scroll
	scrollPage  Page           // which page StageScroll belongs to

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

	Secrets      *model.SecretResult
	AstrLink     *model.SecretResult
	SecretsQuery string
	ModelStatus  model.AstrLinkStatus

	ReportPath string
	Started    time.Time
}

// New makes the app's state.
func New(info model.AppInfo, svc *service.Service) *App {
	a := &App{
		Info:      info,
		Svc:       svc,
		Page:      PageScan,
		Lang:      currentLangPref(),
		CleanSel:  map[string]bool{},
		BlockPlan: svc.BlockPlan(),
		Started:   time.Now(),
		ScanOpts:  model.ScanOptions{MaxFileMB: 128},
	}
	a.ModelStatus = svc.AstrLinkStatus()
	a.LauncherPath = loadLauncherPath()
	a.LauncherDraft = a.LauncherPath
	if a.LauncherPath != "" {
		a.ScanOpts.ExtraLauncherDirs = []string{a.LauncherPath}
	}
	return a
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
				if a.Progress.SubTotal > 0 {
					mono(c, fmt.Sprintf("%d / %d", a.Progress.SubDone, a.Progress.SubTotal), 22, colMuted)
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
		if a.Notice != "" {
			ui.Row(c).Padding(20, 40).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Text(c, a.Notice).FontSize(26).TextColor(colMuted).Grow(1)
				a.ghostButton(c, tr("Dismiss", "關閉", "閉じる"), func() { a.Notice = "" })
			})
		}
		// A page change starts at the top and also cancels a pending jump to
		// the result from the page we just left.
		if a.Page != a.scrollPage {
			a.scrollPage = a.Page
			a.StageScroll.ScrollTo(0, 0, ui.Snappy)
		}
		ui.Scroll(c).Grow(1).Fill().TrackScroll(&a.StageScroll).Children(func() {
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
	a.Notice = ""
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
	a.Notice = ""
	if !remove {
		if a.BlockPlan.BlockTBSBrowser {
			exe, ok := a.Svc.TBSBrowserPath(a.ScanOpts.ExtraLauncherDirs)
			if !ok {
				a.Err = tr("tbs_browser.exe was not found. Set the launcher folder on the verdict page, then try again.", "找不到 tbs_browser.exe。請先在判定頁設定啟動器資料夾。", "tbs_browser.exe が見つかりません。判定ページでランチャーのフォルダを設定してください。")
				return
			}
			a.TBSExe = exe
			a.BlockPlan.ProgramPaths = []string{exe}
		} else {
			a.BlockPlan.ProgramPaths = nil
		}
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
			expectProgram := !remove && len(a.BlockPlan.ProgramPaths) > 0
			v := a.Svc.BlockVerify(expectProgram)
			a.Verify = &v
			// Show the outcome once: the result and the next action live at
			// the end of the page.
			if !remove && a.Page == PageBlock {
				a.StageScroll.ScrollTo(0, math.MaxFloat32, ui.Snappy)
			}
		})
	}()
}

func (a *App) startClean() {
	if a.Busy || a.Win == nil || a.CleanPlan == nil {
		return
	}
	a.Notice = ""
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

func (a *App) startSecretScan() {
	if a.Busy || a.Win == nil {
		return
	}
	a.Notice = ""
	if a.Exposure == nil {
		a.Err = tr("run the exposure check first", "請先做曝險盤點", "先に露出確認をしてください")
		return
	}
	a.Busy = true
	a.BusyLabel = tr("Reading files", "讀取檔案中", "ファイル読み取り中")
	a.Err = ""
	go func() {
		res, err := a.Svc.SecretScan(func(p model.Progress) {
			a.onMain(func() { a.Progress = p })
		})
		a.onMain(func() {
			a.Busy = false
			a.Progress = model.Progress{}
			if err != nil {
				if errors.Is(err, context.Canceled) {
					a.Notice = tr("Scan cancelled", "已取消", "中止しました")
					a.Secrets = res
					return
				}
				a.Err = err.Error()
				return
			}
			a.Secrets = res
		})
	}()
}

func (a *App) startAstrLinkScan() {
	if a.Busy || a.Win == nil {
		return
	}
	a.Notice = ""
	if a.Exposure == nil {
		a.Err = tr("run the exposure check first", "請先做曝險盤點", "先に露出確認をしてください")
		return
	}
	st := a.Svc.AstrLinkStatus()
	a.ModelStatus = st
	if !st.Available {
		if st.Note == "" {
			st.Note = tr("AstrLink model is not available in this build.",
				"此版本沒有可用的 AstrLink 模型。",
				"このビルドには AstrLink モデルがありません。")
		}
		a.Err = st.Note
		return
	}
	a.Busy = true
	a.BusyLabel = tr("Reading with the local model", "本地模型讀取中", "ローカルモデルで読み取り中")
	a.Err = ""
	go func() {
		res, err := a.Svc.AstrLinkScan(func(p model.Progress) {
			a.onMain(func() { a.Progress = p })
		})
		a.onMain(func() {
			a.Busy = false
			a.Progress = model.Progress{}
			if err != nil {
				if errors.Is(err, context.Canceled) {
					a.Notice = tr("Scan cancelled", "已取消", "中止しました")
					a.AstrLink = res
					return
				}
				a.Err = err.Error()
				return
			}
			a.AstrLink = res
		})
	}()
}

func (a *App) startExposure() {
	if a.Busy || a.Win == nil {
		return
	}
	a.Notice = ""
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
			// The content scans belong to the previous path result. Drop
			// them so the panel never shows findings for files the new
			// catalogue run no longer lists.
			a.Secrets = nil
			a.AstrLink = nil
			a.SecretsQuery = ""
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

// validateLauncherDir accepts an absolute, existing directory and returns it
// cleaned. The interface never hands an unchecked path to the scanner.
func validateLauncherDir(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%s", tr("Enter a launcher folder.", "請輸入啟動器資料夾。", "ランチャーのフォルダを入力してください。"))
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("%s", tr("Use an absolute path.", "請使用絕對路徑。", "絶対パスを使ってください。"))
	}
	cleaned := filepath.Clean(raw)
	st, err := os.Stat(cleaned)
	if err != nil {
		return "", fmt.Errorf("%s", tr("That path does not exist.", "路徑不存在。", "そのパスは存在しません。"))
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s", tr("That path is not a folder.", "路徑不是資料夾。", "そのパスはフォルダではありません。"))
	}
	return cleaned, nil
}

// launcherExists reports whether the saved path still exists, for the status
// line on the verdict page.
func (a *App) launcherExists() bool {
	if a.LauncherPath == "" {
		return false
	}
	st, err := os.Stat(a.LauncherPath)
	return err == nil && st.IsDir()
}

// browseLauncherPath opens the native directory picker and puts the choice in
// the draft. The user still saves, so browsing never changes the setting by
// itself.
func (a *App) browseLauncherPath() {
	if a.Win == nil {
		return
	}
	start := strings.TrimSpace(a.LauncherDraft)
	if start == "" {
		start = a.LauncherPath
	}
	paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
		Parent:      a.Win,
		Title:       tr("Choose the NIKKE launcher folder", "選擇 NIKKE 啟動器資料夾", "NIKKE ランチャーのフォルダを選択"),
		DefaultPath: start,
		Directory:   true,
	})
	if err != nil || len(paths) == 0 {
		return
	}
	a.LauncherDraft = paths[0]
	a.LauncherErr = ""
}

// saveLauncherPathAndScan persists a validated path, updates the scan options,
// and starts a fresh scan so the verdict reflects the new location.
func (a *App) saveLauncherPathAndScan() {
	cleaned, err := validateLauncherDir(a.LauncherDraft)
	if err != nil {
		a.LauncherErr = err.Error()
		return
	}
	if err := saveLauncherPath(cleaned); err != nil {
		a.LauncherErr = err.Error()
		return
	}
	a.LauncherErr = ""
	a.LauncherPath = cleaned
	a.LauncherDraft = cleaned
	a.ScanOpts.ExtraLauncherDirs = []string{cleaned}
	a.startScan()
}

// clearLauncherPath removes the override and returns discovery to automatic
// only. It does not scan on its own.
func (a *App) clearLauncherPath() {
	if err := saveLauncherPath(""); err != nil {
		a.LauncherErr = err.Error()
		return
	}
	a.LauncherErr = ""
	a.LauncherPath = ""
	a.LauncherDraft = ""
	a.ScanOpts.ExtraLauncherDirs = nil
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
