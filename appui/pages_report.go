package appui

import (
	"fmt"

	"github.com/egoist/mygo/ui"
)

func (a *App) reportPage(c *ui.Context) {
	data := a.Svc.ReportData()

	verdict := data.Scan.Verdict
	if verdict == "" {
		verdict = "NONE"
	}
	findings := len(data.Scan.Findings)
	if findings == 0 {
		findings = a.FindingCount
	}

	ui.Column(c).Gap(18).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			micro(c, tr("Step 06 / Report", "步驟 06 / 報告", "手順 06 / 報告"), colAcid)
			display(c, "REPORT", 86, colInk)
			mono(c, tr("Everything the app saw and did, in one file. Saved locally, never uploaded.", "本機所見所做，寫成一份檔。只存本機，不上傳。", "本アプリが見て行ったことを1ファイルに。端末内のみ、送信しません。"), 24, colMuted)
		})

		ui.Row(c).Gap(40).Children(func() {
			a.stat(c, verdict, tr("Verdict", "判定", "判定"), verdictColor(verdict))
			a.stat(c, fmt.Sprint(findings), tr("Findings", "發現", "検出"), colInk)
			a.stat(c, fmt.Sprint(len(data.Actions)), tr("Actions", "動作", "操作"), colInk)
			if data.Exposure != nil {
				present := 0
				for _, it := range data.Exposure.Items {
					if it.Exists {
						present++
					}
				}
				a.stat(c, fmt.Sprint(present), tr("Exposed paths", "曝險路徑", "露出経路"), colDanger)
			}
		})

		ui.Row(c).Gap(10).Children(func() {
			a.actionButton(c, tr("Save report", "儲存報告", "報告を保存"), true, a.saveReport)
			ui.Spacer(c)
			if a.ReportPath != "" {
				mono(c, clamp(a.ReportPath, 110), 20, colMuted).SingleLine()
			}
		})

		rule(c)

		ui.Column(c).Gap(6).Children(func() {
			micro(c, tr("Actions this session", "本次動作", "今回の操作"), colDim)
			if len(data.Actions) == 0 {
				mono(c, tr("Nothing yet.", "尚無。", "まだありません。"), 20, colDim)
				return
			}
			for _, act := range data.Actions {
				ui.Row(c).Gap(12).Children(func() {
					mono(c, act.At.Format("15:04:05"), 18, colDim).Width(120)
					mono(c, upper(act.Kind), 18, colAcid).Width(140)
					mono(c, clamp(act.Detail, 120), 20, colMuted).SingleLine()
				})
			}
		})

		p := panel(c)
		p.Children(func() {
			micro(c, tr("What this report cannot do", "報告做不到的事", "報告ではできないこと"), colWarn)
			for _, line := range []string{
				tr("Prove that nothing else was taken: the agent could run any command while it lived.", "無法證明沒被拿走別的：agent 存活時可執行任何命令。", "他に持ち出されていないことは証明できません。生存中のエージェントは任意の命令を実行できました。"),
				tr("Show which commands the attacker ran: the launcher logs do not record them.", "無法顯示攻擊者下了哪些指令：啟動器日誌沒記。", "攻撃者の命令は表示できません。ランチャーログに記録がありません。"),
				tr("Replace rotating passwords, revoking tokens and moving wallet funds.", "不能代替改密碼、撤銷 token、轉移錢包。", "パスワード変更、token 失効、ウォレット資金の移動の代わりにはなりません。"),
				tr("Replace reinstalling the operating system, which the public report calls the safest option.", "不能代替重裝系統——公開報告認為那才最安全。", "OS 再インストールの代わりにはなりません。公開報告はそれが最も安全だとしています。"),
			} {
				ui.Row(c).Gap(8).Children(func() {
					mono(c, "—", 20, colWarn)
					ui.Text(c, line).FontSize(24).TextColor(colMuted).Grow(1)
				})
			}
		})
	})
}
