package appui

import (
	"fmt"

	"github.com/egoist/mygo/ui"

	"github.com/owogametools/k2f-purge/internal/model"
)

func (a *App) buildCleanPlan() {
	plan, err := a.Svc.CleanPlan()
	if err != nil {
		a.Err = err.Error()
		return
	}
	a.CleanPlan = plan
	a.CleanSel = map[string]bool{}
	for _, it := range plan.Items {
		a.CleanSel[it.ID] = true
	}
}

func (a *App) cleanPage(c *ui.Context) {
	ui.Column(c).Gap(18).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			micro(c, tr("Step 04 / Cleanup", "步驟 04 / 清理", "手順 04 / 清掃"), colAcid)
			display(c, "ISOLATE", 86, colInk)
			mono(c, tr("Quarantine first. Permanent deletion is a separate, explicit choice.", "先隔離。永久刪除是另一次明確選擇。", "まず隔離。完全削除は別の明確な選択です。"), 12, colMuted)
		})

		if a.CleanPlan == nil {
			a.emptyState(c, tr("No cleanup plan", "尚無清理計畫", "清掃計画なし"),
				tr("Build a plan from the last scan. Every path is checked against a hard allowlist before anything moves.", "依上次掃描建立計畫。每條路徑都會先過白名單。", "前回の走査から計画を作ります。移動前に全経路を許可リストで確認します。"),
				tr("Build plan", "建立計畫", "計画作成"), a.buildCleanPlan)
		} else {
			if len(a.CleanPlan.Warnings) > 0 {
				p := panel(c)
				p.Children(func() {
					micro(c, tr("Warnings", "警告", "警告"), colWarn)
					for _, w := range a.CleanPlan.Warnings {
						mono(c, w, 10, colWarn).SingleLine()
					}
				})
			}

			ui.Row(c).AlignItems(ui.Center).Children(func() {
				micro(c, trf("%d items", "%d 項", "%d 件", len(a.CleanPlan.Items)), colDim)
				ui.Spacer(c)
				a.ghostButton(c, tr("Rebuild plan", "重建計畫", "計画再作成"), a.buildCleanPlan)
			})

			ui.Column(c).Gap(8).Children(func() {
				for _, it := range a.CleanPlan.Items {
					a.cleanItem(c, it)
				}
			})

			p := panel(c)
			p.Children(func() {
				micro(c, tr("Action", "動作", "操作"), colDim)
				ui.Row(c).Gap(16).AlignItems(ui.Center).Children(func() {
					ui.Segmented(c, &a.CleanMode, tr("Quarantine", "隔離", "隔離"), tr("Delete permanently", "永久刪除", "完全削除"))
					ui.Spacer(c)
					if a.CleanMode == 1 {
						ui.TextInput(c, &a.Confirm).Placeholder(tr("Type PURGE", "輸入 PURGE", "PURGE と入力")).Width(170).Label(tr("Confirmation", "確認", "確認"))
					}
					if a.Busy {
						mono(c, tr("working…", "處理中…", "処理中…"), 10, colMuted)
						return
					}
					a.actionButton(c, tr("Apply", "執行", "実行"), true, a.startClean)
				})
				if a.CleanPlan.RequiresRestart {
					mono(c, tr("A locked file needs a restart to be removed.", "鎖定檔需重開機才能移除。", "ロック中のファイルは再起動後に削除されます。"), 10, colWarn)
				}
			})
		}

		if a.CleanResult != nil {
			p := panel(c)
			p.Children(func() {
				micro(c, tr("Result", "結果", "結果"), colDim)
				ui.Row(c).Gap(36).Children(func() {
					a.stat(c, fmt.Sprint(a.CleanResult.Quarantined), tr("Quarantined", "已隔離", "隔離済"), colAcid)
					a.stat(c, fmt.Sprint(a.CleanResult.Deleted), tr("Deleted", "已刪除", "削除済"), colDanger)
					a.stat(c, fmt.Sprint(a.CleanResult.Skipped), tr("Skipped", "已略過", "省略"), colMuted)
				})
				if a.CleanResult.QuarantineDir != "" {
					mono(c, clamp(a.CleanResult.QuarantineDir, 120), 10, colMuted).SingleLine()
				}
				for _, f := range a.CleanResult.Failures {
					mono(c, "FAIL  "+f, 10, colDanger).SingleLine()
				}
				if a.CleanResult.RequiresRestart {
					mono(c, tr("Restart the machine to finish removing a locked file.", "重開機後才能刪完鎖定檔。", "ロック中のファイルは再起動後に削除できます。"), 10, colWarn)
				}
			})
		}

		rule(c)

		ui.Row(c).AlignItems(ui.Center).Children(func() {
			micro(c, tr("Quarantine", "隔離區", "隔離庫"), colDim)
			ui.Spacer(c)
			a.ghostButton(c, tr("Refresh", "重新整理", "更新"), a.loadQuarantine)
			if a.ShowQuarant && len(a.Quarantine) > 0 {
				a.ghostButton(c, tr("Restore selected", "還原所選", "選択を復元"), a.restoreQuarantine)
				a.ghostButton(c, tr("Purge selected", "清除所選", "選択を消去"), a.purgeQuarantine)
			}
		})

		if !a.ShowQuarant || len(a.Quarantine) == 0 {
			mono(c, tr("Nothing listed. Quarantined files stay under the app's data folder and can be restored.", "尚無項目。隔離檔在應用資料夾，可還原。", "項目なし。隔離ファイルはアプリ資料フォルダにあり、復元できます。"), 10, colDim)
		} else {
			for _, e := range a.Quarantine {
				sel := a.CleanSel["q:"+e.ID]
				ui.Row(c).Gap(12).Padding(10, 12).Radius(8).Background(colSurface).
					Border(1, colLineSoft).AlignItems(ui.Center).
					Children(func() {
						cb := ui.Checkbox(c, &sel, "").Label(tr("Select ", "選取 ", "選択 ") + e.OriginalPath)
						if cb.Changed() {
							a.CleanSel["q:"+e.ID] = sel
						}
						ui.Column(c).Gap(2).Grow(1).Children(func() {
							mono(c, clamp(e.OriginalPath, 110), 10, colInk).SingleLine()
							mono(c, e.RuleID+" · "+sizeFmt(e.Size), 9, colDim).SingleLine()
						})
					})
			}
		}
	})
}

func (a *App) cleanItem(c *ui.Context, it model.CleanItem) {
	sel := a.CleanSel[it.ID]
	row := ui.Row(c).Gap(12).Padding(12).Radius(8).
		Background(colSurface).Border(1, colLineSoft).AlignItems(ui.Center)
	row.Children(func() {
		cb := ui.Checkbox(c, &sel, "").Label(tr("Select ", "選取 ", "選択 ") + it.Path)
		if cb.Changed() {
			a.CleanSel[it.ID] = sel
		}
		ui.Column(c).Gap(3).Grow(1).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				chip(c, it.Kind, colMuted)
				mono(c, clamp(it.Path, 100), 10, colInk).SingleLine()
			})
			ui.Text(c, pick3(it.Reason, it.ReasonZH, it.ReasonJA)).FontSize(11).TextColor(colDim)
			mono(c, sizeFmt(it.Size), 9, colDim)
		})
	})
	if row.Hovered() {
		row.Background(colSurface2)
	}
}
