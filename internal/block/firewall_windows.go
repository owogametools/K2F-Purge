//go:build windows

package block

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/owogametools/k2f-purge/internal/model"
)

func applyFirewall(ctx context.Context, ips []string, persist bool) (rules []model.FirewallRule, persisted bool, warnings, failures []string) {
	if err := refuseRealFirewall(); err != nil {
		return nil, false, nil, []string{err.Error()}
	}
	persisted = persist // netsh rules survive reboot on their own
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			failures = append(failures, "invalid IP: "+ip)
			continue
		}
		name := ruleName(ip)
		installed, note := windowsRulePresent(ctx, name, ip)
		if installed {
			rules = append(rules, model.FirewallRule{Name: name, Detail: "already present", Installed: true})
			continue
		}
		_, stderr, err := run(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			"name="+name,
			"dir=out",
			"action=block",
			"remoteip="+ip,
			"enable=yes",
			"profile=any",
		)
		if err != nil {
			failures = append(failures, fmt.Sprintf("add %s: %v %s", name, err, strings.TrimSpace(stderr)))
			rules = append(rules, model.FirewallRule{Name: name, Detail: note, Installed: false})
			continue
		}
		rules = append(rules, model.FirewallRule{Name: name, Detail: "added", Installed: true})
	}
	return rules, persisted, warnings, failures
}

func removeFirewall(ctx context.Context) (warnings, failures []string) {
	if err := refuseRealFirewall(); err != nil {
		return nil, []string{err.Error()}
	}
	for _, ip := range defaultIPs {
		name := ruleName(ip)
		_, stderr, err := run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		if err != nil {
			// delete of a missing rule is not fatal
			if strings.Contains(strings.ToLower(stderr+err.Error()), "no rules") {
				continue
			}
			failures = append(failures, fmt.Sprintf("delete %s: %v %s", name, err, strings.TrimSpace(stderr)))
		}
	}
	return warnings, failures
}

func verifyFirewall(ctx context.Context, ips []string) (bool, []string) {
	if err := refuseRealFirewall(); err != nil {
		return false, []string{err.Error()}
	}
	ok := true
	var notes []string
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			ok = false
			notes = append(notes, "invalid IP: "+ip)
			continue
		}
		name := ruleName(ip)
		present, note := windowsRulePresent(ctx, name, ip)
		if !present {
			ok = false
		}
		notes = append(notes, note)
	}
	return ok, notes
}

func windowsRulePresent(ctx context.Context, name, ip string) (bool, string) {
	stdout, stderr, err := run(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name="+name)
	out := stdout + stderr
	lower := strings.ToLower(out)
	if err != nil && !strings.Contains(lower, "no rules") {
		return false, fmt.Sprintf("%s: %v", name, err)
	}
	if strings.Contains(lower, "no rules match") || strings.Contains(lower, "no rules") {
		return false, name + ": missing"
	}
	if strings.Contains(out, ip) || strings.Contains(out, name) {
		return true, name + ": present"
	}
	return false, name + ": missing"
}

func flushDNS(ctx context.Context) error {
	if err := refuseRealFirewall(); err != nil {
		return err
	}
	_, stderr, err := run(ctx, "ipconfig", "/flushdns")
	if err != nil {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(stderr))
	}
	return nil
}
