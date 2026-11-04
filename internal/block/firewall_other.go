//go:build !windows && !linux && !darwin

package block

import (
	"context"
	"fmt"

	"github.com/owogametools/k2f-purge/internal/model"
)

func applyFirewall(ctx context.Context, ips []string, persist bool) ([]model.FirewallRule, bool, []string, []string) {
	return nil, false, nil, []string{fmt.Sprintf("firewall: unsupported OS")}
}

func removeFirewall(ctx context.Context) ([]string, []string) {
	return nil, []string{"firewall: unsupported OS"}
}

func verifyFirewall(ctx context.Context, ips []string) (bool, []string) {
	return false, []string{"firewall: unsupported OS"}
}

func flushDNS(ctx context.Context) error {
	return fmt.Errorf("flush DNS: unsupported OS")
}

// Program blocking is Windows-only; the interface never offers it here.
func applyProgramFirewall(ctx context.Context, programs []string) ([]model.FirewallRule, []string, []string) {
	return nil, nil, []string{"tbs_browser.exe blocking is supported on Windows only"}
}

func removeProgramFirewall(ctx context.Context) ([]string, []string) {
	return nil, nil
}

func verifyProgramFirewall(ctx context.Context) (bool, []string) {
	return false, []string{"tbs_browser.exe blocking is supported on Windows only"}
}
