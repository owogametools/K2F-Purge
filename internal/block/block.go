// Package block applies and removes the K2F PURGE hosts and firewall
// blocks. Commands are always exec.Command(bin, args...); IP strings
// are accepted only after net.ParseIP.
package block

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

var defaultDomains = []string{
	"insightjs.com",
	"www.insightjs.com",
	"analytics.insightjs.com",
	"insightjs.org",
	"www.insightjs.org",
}

var defaultIPs = []string{
	"89.127.233.127",
	"89.126.250.172",
}

// Plan builds a default block plan. Empty domains/IPs fall back to the
// built-in IOC list. Invalid IPs and hostnames are dropped.
func Plan(domains, ips []string) model.BlockPlan {
	p := model.BlockPlan{
		UseHosts:    true,
		UseFirewall: true,
		Persist:     true,
		FlushDNS:    true,
	}
	if len(domains) == 0 {
		p.Domains = append([]string(nil), defaultDomains...)
	} else {
		p.Domains = sanitizeDomains(domains)
	}
	if len(ips) == 0 {
		p.IPs = append([]string(nil), defaultIPs...)
	} else {
		good, _ := validateIPs(ips)
		p.IPs = good
	}
	return p
}

// Apply writes the hosts block and/or firewall rules. Partial failures
// are reported on the status; the system is never left silently half
// done without a Failure or Warning.
func Apply(ctx context.Context, p model.BlockPlan, emit func(model.Progress)) (*model.BlockStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	st := &model.BlockStatus{}
	total := 0
	if p.UseHosts {
		total++
	}
	if p.UseFirewall {
		total++
	}
	if p.FlushDNS {
		total++
	}
	done := 0

	if p.UseHosts {
		progress(emit, done, total, "hosts")
		if err := applyHosts(p.Domains); err != nil {
			st.Failures = append(st.Failures, "hosts: "+err.Error())
		} else {
			st.HostsApplied = true
			st.HostsPath = hostsPath()
		}
		done++
	}
	if err := ctx.Err(); err != nil {
		st.Failures = append(st.Failures, err.Error())
		return st, err
	}

	if p.UseFirewall {
		progress(emit, done, total, "firewall")
		ips, bad := validateIPs(p.IPs)
		for _, b := range bad {
			st.Failures = append(st.Failures, "invalid IP: "+b)
		}
		if len(ips) == 0 {
			st.Failures = append(st.Failures, "firewall: no valid IPs")
		} else {
			rules, persisted, warns, fails := applyFirewall(ctx, ips, p.Persist)
			st.Rules = rules
			st.Persisted = persisted
			st.Warnings = append(st.Warnings, warns...)
			st.Failures = append(st.Failures, fails...)
		}
		done++
	}
	if err := ctx.Err(); err != nil {
		st.Failures = append(st.Failures, err.Error())
		return st, err
	}

	if p.FlushDNS {
		progress(emit, done, total, "flush-dns")
		if err := flushDNS(ctx); err != nil {
			st.Warnings = append(st.Warnings, "flush DNS: "+err.Error())
		}
		done++
	}

	v := Verify(ctx)
	st.Verified = v.AllOK
	if !v.AllOK && v.HostsDetail != "" {
		st.Warnings = append(st.Warnings, "verify hosts: "+v.HostsDetail)
	}
	progress(emit, done, total, "done")
	return st, nil
}

// Remove deletes only this tool's hosts marker and named firewall rules.
func Remove(ctx context.Context, emit func(model.Progress)) (*model.BlockStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	st := &model.BlockStatus{HostsPath: hostsPath()}
	progress(emit, 0, 2, "hosts")
	if err := removeHosts(); err != nil {
		st.Failures = append(st.Failures, "hosts: "+err.Error())
	} else {
		st.HostsApplied = false
	}
	progress(emit, 1, 2, "firewall")
	warns, fails := removeFirewall(ctx)
	st.Warnings = append(st.Warnings, warns...)
	st.Failures = append(st.Failures, fails...)
	v := Verify(ctx)
	st.Verified = !v.HostsOK && !v.FirewallOK
	st.Rules = nil
	st.Persisted = false
	progress(emit, 2, 2, "done")
	return st, nil
}

// Verify checks the hosts marker and the named firewall rules. It does
// not query the network: a LookupHost of an unblocked name would leak
// DNS, which this tool must never do.
func Verify(ctx context.Context) model.BlockVerify {
	v := model.BlockVerify{}
	ok, detail := verifyHostsFile(defaultDomains)
	v.HostsOK = ok
	v.HostsDetail = detail

	fwOK, notes := verifyFirewall(ctx, defaultIPs)
	v.FirewallOK = fwOK
	v.FirewallNotes = notes
	v.AllOK = v.HostsOK && v.FirewallOK
	return v
}

func progress(emit func(model.Progress), done, total int, current string) {
	if emit != nil {
		emit(model.Progress{Done: done, Total: total, Current: current})
	}
}

func validateIPs(ips []string) (good, bad []string) {
	seen := map[string]struct{}{}
	for _, raw := range ips {
		raw = strings.TrimSpace(raw)
		parsed := net.ParseIP(raw)
		if parsed == nil {
			if raw != "" {
				bad = append(bad, raw)
			}
			continue
		}
		s := parsed.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		good = append(good, s)
	}
	return good, bad
}

func sanitizeDomains(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimPrefix(d, "https://")
		d = strings.Trim(d, "/")
		if d == "" || !validHostname(d) {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func validHostname(d string) bool {
	if len(d) < 1 || len(d) > 253 {
		return false
	}
	if strings.ContainsAny(d, " \t\r\n;|&$<>`(){}[]\\\"'=/") {
		return false
	}
	if strings.Contains(d, "..") {
		return false
	}
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 63 {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0 && i < len(p)-1)
			if !ok {
				return false
			}
		}
	}
	return true
}

func ruleName(ip string) string {
	return "K2F PURGE - Block " + ip
}

func refuseRealFirewall() error {
	if testing.Testing() && !usingTestRunner {
		return fmt.Errorf("firewall: refused to run real commands in tests")
	}
	return nil
}
