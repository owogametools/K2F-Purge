//go:build linux

package block

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

var (
	linuxPersistDir  = "/etc/k2f-purge"
	linuxNFTFile     = "/etc/k2f-purge/block.nft"
	linuxSystemdUnit = "/etc/systemd/system/k2f-purge-block.service"
)

func applyFirewall(ctx context.Context, ips []string, persist bool) (rules []model.FirewallRule, persisted bool, warnings, failures []string) {
	if err := refuseRealFirewall(); err != nil {
		return nil, false, nil, []string{err.Error()}
	}
	if err := applyNft(ctx, ips); err != nil {
		warnings = append(warnings, "nftables: "+err.Error())
		if err2 := applyIptables(ctx, ips); err2 != nil {
			failures = append(failures, "nftables: "+err.Error(), "iptables: "+err2.Error())
			for _, ip := range ips {
				rules = append(rules, model.FirewallRule{Name: ruleName(ip), Installed: false})
			}
			return rules, false, warnings, failures
		}
		warnings = append(warnings, "using iptables fallback; rules will not survive reboot")
		for _, ip := range ips {
			rules = append(rules, model.FirewallRule{Name: ruleName(ip), Detail: "iptables", Installed: true})
		}
		return rules, false, warnings, failures
	}
	for _, ip := range ips {
		rules = append(rules, model.FirewallRule{Name: ruleName(ip), Detail: "nftables", Installed: true})
	}
	if persist {
		ok, warn := persistLinux(ctx, ips)
		persisted = ok
		if warn != "" {
			warnings = append(warnings, warn)
		}
	}
	return rules, persisted, warnings, failures
}

func applyNft(ctx context.Context, ips []string) error {
	_, stderr, err := run(ctx, "nft", "list", "table", "inet", "k2f_purge")
	if err != nil {
		if _, stderr, err = run(ctx, "nft", "add", "table", "inet", "k2f_purge"); err != nil {
			return fmt.Errorf("add table: %v %s", err, strings.TrimSpace(stderr))
		}
		if _, stderr, err = run(ctx, "nft", "add", "chain", "inet", "k2f_purge", "output",
			"{ type filter hook output priority 0 ; policy accept ; }"); err != nil {
			return fmt.Errorf("add chain: %v %s", err, strings.TrimSpace(stderr))
		}
	}
	// Re-applying must not stack duplicate rules: read the chain once and
	// skip the addresses it already drops.
	existing, _, listErr := run(ctx, "nft", "list", "chain", "inet", "k2f_purge", "output")
	if listErr != nil {
		existing = ""
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return fmt.Errorf("invalid IP %q", ip)
		}
		if strings.Contains(existing, "daddr "+parsed.String()+" drop") {
			continue
		}
		kind := "ip"
		if parsed.To4() == nil {
			kind = "ip6"
		}
		if _, stderr, err = run(ctx, "nft", "add", "rule", "inet", "k2f_purge", "output", kind, "daddr", parsed.String(), "drop"); err != nil {
			return fmt.Errorf("add rule %s: %v %s", ip, err, strings.TrimSpace(stderr))
		}
	}
	return nil
}

func applyIptables(ctx context.Context, ips []string) error {
	var last error
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return fmt.Errorf("invalid IP %q", ip)
		}
		bin := "iptables"
		if parsed.To4() == nil {
			bin = "ip6tables"
		}
		_, _, err := run(ctx, bin, "-C", "OUTPUT", "-d", ip, "-j", "DROP")
		if err == nil {
			continue
		}
		if _, stderr, err := run(ctx, bin, "-I", "OUTPUT", "-d", ip, "-j", "DROP"); err != nil {
			last = fmt.Errorf("%s %s: %v %s", bin, ip, err, strings.TrimSpace(stderr))
		}
	}
	return last
}

func persistLinux(ctx context.Context, ips []string) (bool, string) {
	if testing.Testing() && linuxPersistDir == "/etc/k2f-purge" {
		return false, "persist skipped in tests"
	}
	if err := os.MkdirAll(linuxPersistDir, 0o755); err != nil {
		return false, "/etc not writable (SteamOS readonly?); nftables applied for this boot only: " + err.Error()
	}
	body := nftFile(ips)
	if err := os.WriteFile(linuxNFTFile, []byte(body), 0o644); err != nil {
		return false, "write nft file: " + err.Error()
	}
	unit := systemdUnit()
	if err := os.WriteFile(linuxSystemdUnit, []byte(unit), 0o644); err != nil {
		return false, "write systemd unit: " + err.Error()
	}
	if _, stderr, err := run(ctx, "systemctl", "daemon-reload"); err != nil {
		return false, fmt.Sprintf("systemctl daemon-reload: %v %s", err, strings.TrimSpace(stderr))
	}
	if _, stderr, err := run(ctx, "systemctl", "enable", "--now", "k2f-purge-block.service"); err != nil {
		return false, fmt.Sprintf("systemctl enable: %v %s", err, strings.TrimSpace(stderr))
	}
	return true, ""
}

func nftFile(ips []string) string {
	var b strings.Builder
	b.WriteString("table inet k2f_purge {\n")
	b.WriteString("    chain output {\n")
	b.WriteString("        type filter hook output priority 0; policy accept;\n")
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			b.WriteString("        ip daddr ")
		} else {
			b.WriteString("        ip6 daddr ")
		}
		b.WriteString(parsed.String())
		b.WriteString(" drop\n")
	}
	b.WriteString("    }\n}\n")
	return b.String()
}

func systemdUnit() string {
	nft := "/usr/sbin/nft"
	if filepath.Base(linuxNFTFile) != "" {
		// keep the path we wrote
	}
	return `[Unit]
Description=K2F PURGE outbound IP block
DefaultDependencies=no
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=` + nft + ` -f ` + linuxNFTFile + `
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`
}

func removeFirewall(ctx context.Context) (warnings, failures []string) {
	if err := refuseRealFirewall(); err != nil {
		return nil, []string{err.Error()}
	}
	if !testing.Testing() || linuxPersistDir != "/etc/k2f-purge" {
		_, stderr, err := run(ctx, "systemctl", "disable", "--now", "k2f-purge-block.service")
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("systemctl disable: %v %s", err, strings.TrimSpace(stderr)))
		}
		_ = os.Remove(linuxSystemdUnit)
		_ = os.Remove(linuxNFTFile)
		_ = os.Remove(linuxPersistDir)
		_, _, _ = run(ctx, "systemctl", "daemon-reload")
	}
	if _, stderr, err := run(ctx, "nft", "delete", "table", "inet", "k2f_purge"); err != nil {
		warnings = append(warnings, fmt.Sprintf("nft delete table: %v %s", err, strings.TrimSpace(stderr)))
	}
	for _, ip := range defaultIPs {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		bin := "iptables"
		if parsed.To4() == nil {
			bin = "ip6tables"
		}
		for i := 0; i < 8; i++ {
			if _, _, err := run(ctx, bin, "-D", "OUTPUT", "-d", ip, "-j", "DROP"); err != nil {
				break
			}
		}
	}
	return warnings, failures
}

func verifyFirewall(ctx context.Context, ips []string) (bool, []string) {
	if err := refuseRealFirewall(); err != nil {
		return false, []string{err.Error()}
	}
	stdout, stderr, err := run(ctx, "nft", "list", "table", "inet", "k2f_purge")
	out := stdout + stderr
	if err != nil {
		// iptables fallback
		ok := true
		var notes []string
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				ok = false
				notes = append(notes, "invalid IP: "+ip)
				continue
			}
			bin := "iptables"
			if parsed.To4() == nil {
				bin = "ip6tables"
			}
			if _, _, err := run(ctx, bin, "-C", "OUTPUT", "-d", ip, "-j", "DROP"); err != nil {
				ok = false
				notes = append(notes, ip+": missing")
			} else {
				notes = append(notes, ip+": iptables")
			}
		}
		return ok, notes
	}
	ok := true
	var notes []string
	for _, ip := range ips {
		if !strings.Contains(out, ip) {
			ok = false
			notes = append(notes, ip+": missing from nft table")
		} else {
			notes = append(notes, ip+": nftables")
		}
	}
	return ok, notes
}

func flushDNS(ctx context.Context) error {
	if err := refuseRealFirewall(); err != nil {
		return err
	}
	if _, _, err := run(ctx, "resolvectl", "flush-caches"); err == nil {
		return nil
	}
	if _, _, err := run(ctx, "systemd-resolve", "--flush-caches"); err == nil {
		return nil
	}
	return fmt.Errorf("no resolvectl/systemd-resolve")
}

// Program blocking is Windows-only (the launcher's egress browser runs as a
// Windows process). The interface never offers the option here.
func applyProgramFirewall(ctx context.Context, programs []string) (rules []model.FirewallRule, warnings, failures []string) {
	return nil, nil, []string{"tbs_browser.exe blocking is supported on Windows only"}
}

func removeProgramFirewall(ctx context.Context) (warnings, failures []string) {
	return nil, nil
}

func verifyProgramFirewall(ctx context.Context) (bool, []string) {
	return false, []string{"tbs_browser.exe blocking is supported on Windows only"}
}
