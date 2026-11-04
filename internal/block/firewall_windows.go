//go:build windows

package block

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
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
		stdout, stderr, err := run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		if noRulesMatch(stdout, stderr, err) {
			continue
		}
		if err != nil {
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

// applyProgramFirewall blocks the resolved exe in both directions. The two
// fixed names are deleted first so a re-apply replaces a stale program path
// instead of stacking a second rule with the same name.
func applyProgramFirewall(ctx context.Context, programs []string) (rules []model.FirewallRule, warnings, failures []string) {
	if err := refuseRealFirewall(); err != nil {
		return nil, nil, []string{err.Error()}
	}
	names := []string{tbsRuleOut, tbsRuleIn}
	for _, name := range names {
		stdout, stderr, err := run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		if noRulesMatch(stdout, stderr, err) {
			continue
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("delete %s: %v %s", name, err, strings.TrimSpace(stderr)))
		}
	}
	for _, exe := range programs {
		exe = strings.TrimSpace(exe)
		if exe == "" {
			continue
		}
		for _, r := range []struct{ name, dir string }{
			{tbsRuleOut, "out"},
			{tbsRuleIn, "in"},
		} {
			_, stderr, err := run(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
				"name="+r.name,
				"dir="+r.dir,
				"action=block",
				"program="+exe,
				"enable=yes",
				"profile=any",
			)
			if err != nil {
				failures = append(failures, fmt.Sprintf("add %s: %v %s", r.name, err, strings.TrimSpace(stderr)))
				rules = append(rules, model.FirewallRule{Name: r.name, Detail: exe, Installed: false})
				continue
			}
			rules = append(rules, model.FirewallRule{Name: r.name, Detail: "program " + exe, Installed: true})
		}
	}
	return rules, warnings, failures
}

// removeProgramFirewall deletes the two fixed program rules. Deleting a
// missing rule is not fatal, so a second Remove is harmless.
func removeProgramFirewall(ctx context.Context) (warnings, failures []string) {
	if err := refuseRealFirewall(); err != nil {
		return nil, []string{err.Error()}
	}
	for _, name := range []string{tbsRuleOut, tbsRuleIn} {
		stdout, stderr, err := run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		if noRulesMatch(stdout, stderr, err) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("delete %s: %v %s", name, err, strings.TrimSpace(stderr)))
		}
	}
	return warnings, failures
}

// noRulesMatch reports netsh's "No rules match the specified criteria."
// result. netsh writes that message to stdout, not stderr, and exits 1.
func noRulesMatch(stdout, stderr string, err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(stdout+stderr+err.Error()), "no rules")
}

// verifyProgramFirewall requires both fixed rule names to be present and to
// name tbs_browser.exe, so a rule that still points at a stale path fails.
func verifyProgramFirewall(ctx context.Context) (bool, []string) {
	if err := refuseRealFirewall(); err != nil {
		return false, []string{err.Error()}
	}
	ok := true
	var notes []string
	for _, name := range []string{tbsRuleOut, tbsRuleIn} {
		present, note := windowsProgramRulePresent(ctx, name)
		if !present {
			ok = false
		}
		notes = append(notes, note)
	}
	return ok, notes
}

// windowsProgramRulePresent asks for verbose output because the default
// `show rule` shape omits the Program field. The rule name itself contains
// "tbs_browser.exe", so only the Program line proves the rule points at the
// launcher's browser.
func windowsProgramRulePresent(ctx context.Context, name string) (bool, string) {
	stdout, stderr, err := run(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name="+name, "verbose")
	out := stdout + stderr
	lower := strings.ToLower(out)
	if strings.Contains(lower, "no rules match") {
		return false, name + ": missing"
	}
	if err != nil {
		return false, fmt.Sprintf("%s: %v", name, err)
	}
	if !strings.Contains(out, name) {
		return false, name + ": missing"
	}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Program") {
			continue
		}
		program := strings.TrimSpace(value)
		if strings.EqualFold(filepath.Base(program), "tbs_browser.exe") {
			return true, name + ": present"
		}
		return false, name + ": points at " + program
	}
	return false, name + ": program path missing"
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
