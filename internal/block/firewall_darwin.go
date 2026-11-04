//go:build darwin

package block

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

const (
	darwinAnchorName = "com.k2fpurge"
	darwinPlistLabel = "com.k2fpurge.block"
)

var (
	darwinAnchorPath = "/etc/pf.anchors/com.k2fpurge"
	darwinPlistPath  = "/Library/LaunchDaemons/com.k2fpurge.block.plist"
)

func applyFirewall(ctx context.Context, ips []string, persist bool) (rules []model.FirewallRule, persisted bool, warnings, failures []string) {
	if err := refuseRealFirewall(); err != nil {
		return nil, false, nil, []string{err.Error()}
	}
	body := pfAnchor(ips)
	if testing.Testing() && darwinAnchorPath == "/etc/pf.anchors/com.k2fpurge" {
		failures = append(failures, "refused to write real pf anchor in tests")
		return rules, false, warnings, failures
	}
	if err := os.MkdirAll("/etc/pf.anchors", 0o755); err != nil {
		failures = append(failures, "mkdir pf.anchors: "+err.Error())
		return rules, false, warnings, failures
	}
	if err := os.WriteFile(darwinAnchorPath, []byte(body), 0o644); err != nil {
		failures = append(failures, "write pf anchor: "+err.Error())
		return rules, false, warnings, failures
	}
	if _, stderr, err := run(ctx, "pfctl", "-a", darwinAnchorName, "-f", darwinAnchorPath); err != nil {
		failures = append(failures, fmt.Sprintf("pfctl load: %v %s", err, strings.TrimSpace(stderr)))
		return rules, false, warnings, failures
	}
	if _, stderr, err := run(ctx, "pfctl", "-E"); err != nil {
		warnings = append(warnings, fmt.Sprintf("pfctl -E: %v %s", err, strings.TrimSpace(stderr)))
	}
	for _, ip := range ips {
		rules = append(rules, model.FirewallRule{Name: ruleName(ip), Detail: "pf " + darwinAnchorName, Installed: true})
	}
	if persist {
		if err := writeLaunchDaemon(); err != nil {
			warnings = append(warnings, "LaunchDaemon: "+err.Error())
		} else if _, stderr, err := run(ctx, "launchctl", "bootstrap", "system", darwinPlistPath); err != nil {
			_, stderr2, err2 := run(ctx, "launchctl", "load", darwinPlistPath)
			if err2 != nil {
				warnings = append(warnings, fmt.Sprintf("launchctl: %v %s / %v %s", err, strings.TrimSpace(stderr), err2, strings.TrimSpace(stderr2)))
			} else {
				persisted = true
			}
		} else {
			persisted = true
		}
	}
	return rules, persisted, warnings, failures
}

func pfAnchor(ips []string) string {
	var b strings.Builder
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		b.WriteString("block drop out quick to ")
		b.WriteString(parsed.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func writeLaunchDaemon() error {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + darwinPlistLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>/sbin/pfctl</string>
		<string>-a</string>
		<string>` + darwinAnchorName + `</string>
		<string>-f</string>
		<string>` + darwinAnchorPath + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
`
	return os.WriteFile(darwinPlistPath, []byte(plist), 0o644)
}

func removeFirewall(ctx context.Context) (warnings, failures []string) {
	if err := refuseRealFirewall(); err != nil {
		return nil, []string{err.Error()}
	}
	if _, stderr, err := run(ctx, "pfctl", "-a", darwinAnchorName, "-F", "all"); err != nil {
		warnings = append(warnings, fmt.Sprintf("pfctl flush: %v %s", err, strings.TrimSpace(stderr)))
	}
	if testing.Testing() && darwinAnchorPath == "/etc/pf.anchors/com.k2fpurge" {
		return warnings, failures
	}
	_, stderr, err := run(ctx, "launchctl", "bootout", "system/"+darwinPlistLabel)
	if err != nil {
		_, stderr2, err2 := run(ctx, "launchctl", "unload", darwinPlistPath)
		if err2 != nil {
			warnings = append(warnings, fmt.Sprintf("launchctl unload: %v %s / %v %s", err, strings.TrimSpace(stderr), err2, strings.TrimSpace(stderr2)))
		}
	}
	if err := os.Remove(darwinPlistPath); err != nil && !os.IsNotExist(err) {
		failures = append(failures, "remove plist: "+err.Error())
	}
	if err := os.Remove(darwinAnchorPath); err != nil && !os.IsNotExist(err) {
		failures = append(failures, "remove anchor: "+err.Error())
	}
	return warnings, failures
}

func verifyFirewall(ctx context.Context, ips []string) (bool, []string) {
	if err := refuseRealFirewall(); err != nil {
		return false, []string{err.Error()}
	}
	stdout, stderr, err := run(ctx, "pfctl", "-a", darwinAnchorName, "-s", "rules")
	out := stdout + stderr
	if err != nil {
		return false, []string{fmt.Sprintf("pfctl show: %v %s", err, strings.TrimSpace(stderr))}
	}
	ok := true
	var notes []string
	for _, ip := range ips {
		if !strings.Contains(out, ip) {
			ok = false
			notes = append(notes, ip+": missing from pf anchor")
		} else {
			notes = append(notes, ip+": pf")
		}
	}
	return ok, notes
}

func flushDNS(ctx context.Context) error {
	if err := refuseRealFirewall(); err != nil {
		return err
	}
	_, stderr, err := run(ctx, "dscacheutil", "-flushcache")
	if err != nil {
		return fmt.Errorf("dscacheutil: %v %s", err, strings.TrimSpace(stderr))
	}
	if _, stderr, err := run(ctx, "killall", "-HUP", "mDNSResponder"); err != nil {
		return fmt.Errorf("killall mDNSResponder: %v %s", err, strings.TrimSpace(stderr))
	}
	return nil
}
