package appui

import (
	"github.com/egoist/mygo/ui"
)

func (a *App) blockPage(c *ui.Context) {
	ui.Column(c).Gap(18).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			micro(c, tr("Step 03 / Containment", "步驟 03 / 圍堵", "手順 03 / 封じ込め"), colAcid)
			display(c, "BLOCK", 86, colInk)
			mono(c, tr("Stop the current infrastructure. This does not undo an infection.", "切斷現用基礎設施。無法撤銷感染。", "現行のインフラを遮断します。感染は取り消せません。"), 24, colMuted)
		})

		ui.Row(c).Gap(16).AlignItems(ui.Start).Children(func() {
			p := panel(c).Grow(1)
			p.Children(func() {
				micro(c, tr("What to block", "封鎖項目", "遮断対象"), colDim)
				ui.Checkbox(c, &a.BlockPlan.UseHosts, tr("Hosts file — domains", "Hosts 檔 — 網域", "Hosts ファイル — ドメイン")).Label(tr("Hosts file", "Hosts", "Hosts"))
				ui.Checkbox(c, &a.BlockPlan.UseFirewall, tr("Firewall — outbound IPs", "防火牆 — 出站 IP", "Firewall — 送信 IP")).Label(tr("Firewall", "防火牆", "Firewall"))
				ui.Checkbox(c, &a.BlockPlan.Persist, tr("Keep the firewall rules after reboot", "重開機後保留規則", "再起動後も規則を保持")).Label(tr("Persist", "持久化", "永続"))
				ui.Checkbox(c, &a.BlockPlan.FlushDNS, tr("Flush the DNS cache", "清除 DNS 快取", "DNS キャッシュを消去")).Label(tr("Flush DNS", "清 DNS", "DNS消去"))
				ui.Spacer(c)
				ui.Row(c).Gap(8).Children(func() {
					if a.Busy {
						return
					}
					a.actionButton(c, tr("Apply block", "套用封鎖", "遮断を適用"), true, func() { a.startBlock(false) })
					a.ghostButton(c, tr("Remove block", "解除封鎖", "遮断を解除"), func() { a.startBlock(true) })
				})
			})

			p2 := panel(c).Grow(1)
			p2.Children(func() {
				micro(c, tr("Indicators", "指標", "指標"), colDim)
				for _, d := range a.BlockPlan.Domains {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						mono(c, "HOST", 18, colAcid)
						mono(c, d, 22, colInk)
					})
				}
				for _, ip := range a.BlockPlan.IPs {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						mono(c, "IP", 18, colWarn)
						mono(c, ip, 22, colInk)
					})
				}
				ui.Text(c, tr("Domains are pinned in the hosts file. IPs are dropped outbound by the system firewall.", "網域寫入 hosts。IP 由系統防火牆擋出站。", "ドメインは hosts に固定。IP はファイアウォールで送信を遮断します。")).
					FontSize(22).TextColor(colDim)
			})
		})

		if a.Block != nil {
			p := panel(c)
			p.Children(func() {
				micro(c, tr("Result", "結果", "結果"), colDim)
				a.statusLine(c, tr("Hosts file", "Hosts 檔", "Hosts ファイル"), a.Block.HostsApplied, a.Block.HostsPath)
				for _, r := range a.Block.Rules {
					a.statusLine(c, r.Name, r.Installed, r.Detail)
				}
				if a.Block.Persisted {
					a.statusLine(c, tr("Persisted across reboot", "重開機後仍在", "再起動後も有効"), true, "")
				}
				for _, w := range a.Block.Warnings {
					mono(c, "WARN  "+w, 20, colWarn).SingleLine()
				}
				for _, f := range a.Block.Failures {
					mono(c, "FAIL  "+f, 20, colDanger).SingleLine()
				}
			})
		}

		if a.Verify != nil {
			p := panel(c)
			p.Children(func() {
				micro(c, tr("Verification", "驗證", "検証"), colDim)
				a.statusLine(c, tr("Domains resolve to a sinkhole", "網域解析到黑洞", "ドメインはシンクホールへ"), a.Verify.HostsOK, a.Verify.HostsDetail)
				a.statusLine(c, tr("Firewall rules are present", "防火牆規則已在", "FW 規則あり"), a.Verify.FirewallOK, "")
				for _, n := range a.Verify.FirewallNotes {
					mono(c, "  "+n, 20, colDim).SingleLine()
				}
			})
		}
		ui.Row(c).Gap(10).Children(func() {
			a.ghostButton(c, tr("Verify", "驗證", "検証"), func() {
				v := a.Svc.BlockVerify()
				a.Verify = &v
			})
			ui.Spacer(c)
			a.ghostButton(c, tr("Continue to cleanup", "繼續清理", "清掃へ進む"), func() { a.Page = PageClean })
		})
	})
}

func (a *App) statusLine(c *ui.Context, label string, ok bool, detail string) {
	mark, color := "×", colDanger
	if ok {
		mark, color = "✓", colAcid
	}
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		mono(c, mark, 22, color)
		ui.Text(c, label).FontSize(24).TextColor(colInk).Grow(1)
		if detail != "" {
			mono(c, clamp(detail, 80), 20, colDim).SingleLine()
		}
	})
}
