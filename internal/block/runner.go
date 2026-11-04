package block

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner runs an external binary with a argv list. Tests inject a fake
// so Apply/Remove never touch the real firewall.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if name == "" {
		return "", "", fmt.Errorf("empty command name")
	}
	if strings.ContainsAny(name, " \t\n;&|<>") {
		return "", "", fmt.Errorf("refusing to run shelled command name %q", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	hideConsole(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

var (
	runner          Runner = execRunner{}
	usingTestRunner bool
)

func run(ctx context.Context, name string, args ...string) (string, string, error) {
	if runner == nil {
		return "", "", fmt.Errorf("no command runner")
	}
	return runner.Run(ctx, name, args...)
}
