//go:build windows

package block

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

type fakeCall struct {
	name string
	args []string
}

type programRunner struct {
	calls []fakeCall
	// show maps a rule name to its verbose `show rule` output.
	show map[string]string
}

// noRules is what netsh prints (on stdout) and exits 1 for a rule that is
// not installed.
const noRules = "\r\nNo rules match the specified criteria.\r\n"

func (r *programRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, fakeCall{name: name, args: append([]string(nil), args...)})
	if len(args) >= 3 && args[0] == "advfirewall" && args[1] == "firewall" && args[2] == "show" {
		for _, a := range args {
			if rule, ok := strings.CutPrefix(a, "name="); ok {
				if out, ok := r.show[rule]; ok {
					return out, "", nil
				}
				return noRules, "", errors.New("exit status 1")
			}
		}
	}
	if len(args) >= 3 && args[0] == "advfirewall" && args[1] == "firewall" && args[2] == "delete" {
		return noRules, "", errors.New("exit status 1")
	}
	return "Ok.\n", "", nil
}

func withProgramRunner(t *testing.T, r *programRunner) {
	t.Helper()
	old := runner
	runner = r
	usingTestRunner = true
	t.Cleanup(func() {
		runner = old
		usingTestRunner = false
	})
}

func TestProgramFirewallApplyShapesAndReapply(t *testing.T) {
	rec := &programRunner{}
	withProgramRunner(t, rec)
	exe := `C:\Games\NIKKE\Launcher\intl_service\tbs_browser.exe`

	rules, warns, fails := applyProgramFirewall(context.Background(), []string{exe})
	if len(fails) != 0 {
		t.Fatalf("failures: %v", fails)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	if len(rules) != 2 || !rules[0].Installed || !rules[1].Installed {
		t.Fatalf("rules: %+v", rules)
	}
	if rules[0].Name != tbsRuleOut || rules[1].Name != tbsRuleIn {
		t.Fatalf("rule names: %+v", rules)
	}

	// Delete both fixed names before adding, so a re-apply replaces rather
	// than stacking.
	if len(rec.calls) != 4 {
		t.Fatalf("calls: %+v", rec.calls)
	}
	for i, want := range []string{"delete", "delete", "add", "add"} {
		if rec.calls[i].args[2] != want {
			t.Fatalf("call %d: %v, want %s", i, rec.calls[i].args, want)
		}
	}
	for _, dir := range []struct{ rule, direction string }{
		{tbsRuleOut, "out"},
		{tbsRuleIn, "in"},
	} {
		found := false
		for _, c := range rec.calls {
			if c.args[2] != "add" {
				continue
			}
			joined := strings.Join(c.args, " ")
			if strings.Contains(joined, "name="+dir.rule) &&
				strings.Contains(joined, "dir="+dir.direction) &&
				strings.Contains(joined, "action=block") &&
				strings.Contains(joined, "program="+exe) &&
				strings.Contains(joined, "enable=yes") &&
				strings.Contains(joined, "profile=any") {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s add: %+v", dir.direction, rec.calls)
		}
	}

	// Applying again deletes first again; the add count stays two per run.
	rec.calls = nil
	rules, _, fails = applyProgramFirewall(context.Background(), []string{exe})
	if len(fails) != 0 || len(rules) != 2 {
		t.Fatalf("re-apply: rules=%+v fails=%v", rules, fails)
	}
	adds := 0
	for _, c := range rec.calls {
		if c.args[2] == "add" {
			adds++
		}
	}
	if adds != 2 {
		t.Fatalf("re-apply adds %d rules, want 2: %+v", adds, rec.calls)
	}
}

func TestProgramFirewallVerifyParsesShowOutput(t *testing.T) {
	const ruleOut = "Rule Name:                            K2F PURGE - Block tbs_browser.exe (out)\r\n" +
		"Direction:                            Out\r\n" +
		"Program:                              C:\\Games\\NIKKE\\Launcher\\intl_service\\tbs_browser.exe\r\n"
	const ruleIn = "Rule Name:                            K2F PURGE - Block tbs_browser.exe (in)\r\n" +
		"Direction:                            In\r\n" +
		"Program:                              C:\\Games\\NIKKE\\Launcher\\intl_service\\tbs_browser.exe\r\n"

	rec := &programRunner{show: map[string]string{tbsRuleOut: ruleOut, tbsRuleIn: ruleIn}}
	withProgramRunner(t, rec)
	ok, notes := verifyProgramFirewall(context.Background())
	if !ok {
		t.Fatalf("expected present: %v", notes)
	}
	if len(notes) != 2 {
		t.Fatalf("notes: %v", notes)
	}
	// The verbose form is required; the default output omits the Program
	// field, so a presence check against it would never prove the path.
	for _, c := range rec.calls {
		if c.args[2] == "show" && (len(c.args) < 6 || c.args[len(c.args)-1] != "verbose") {
			t.Fatalf("show must be verbose: %v", c.args)
		}
	}

	// Same rule name, wrong program: the name itself contains
	// "tbs_browser.exe", so this must not pass.
	rec.show[tbsRuleOut] = "Rule Name:                            K2F PURGE - Block tbs_browser.exe (out)\r\n" +
		"Direction:                            Out\r\n" +
		"Program:                              C:\\Games\\NIKKE\\elsewhere\\other.exe\r\n"
	ok, notes = verifyProgramFirewall(context.Background())
	if ok {
		t.Fatalf("a rule pointing at another program must not count as present: %v", notes)
	}
	for _, n := range notes {
		if strings.Contains(n, "points at") {
			return
		}
	}
	t.Fatalf("expected a wrong-program note, got %v", notes)
}

func TestProgramRulePresentRejectsNonVerboseShape(t *testing.T) {
	// A rule name alone is not evidence; the Program line is.
	rec := &programRunner{show: map[string]string{
		tbsRuleOut: "Rule Name:                            K2F PURGE - Block tbs_browser.exe (out)\r\n" +
			"Direction:                            Out\r\n" +
			"Action:                               Block\r\n",
	}}
	withProgramRunner(t, rec)
	present, note := windowsProgramRulePresent(context.Background(), tbsRuleOut)
	if present {
		t.Fatalf("rule without a Program line must not be present: %s", note)
	}
	if !strings.Contains(note, "program path missing") {
		t.Fatalf("note: %s", note)
	}
}

func TestProgramFirewallRemoveIsHarmless(t *testing.T) {
	rec := &programRunner{}
	withProgramRunner(t, rec)
	// The fake delete reports "no rules match"; Remove must not fail.
	warns, fails := removeProgramFirewall(context.Background())
	if len(warns) != 0 || len(fails) != 0 {
		t.Fatalf("remove: warns=%v fails=%v", warns, fails)
	}
	if len(rec.calls) != 2 {
		t.Fatalf("calls: %+v", rec.calls)
	}
}

func TestApplyWithProgramPathsAddsRules(t *testing.T) {
	withHosts(t, "")
	const program = "Program:                              C:\\Games\\NIKKE\\Launcher\\intl_service\\tbs_browser.exe\r\n"
	rec := &programRunner{show: map[string]string{
		tbsRuleOut: "Rule Name: K2F PURGE - Block tbs_browser.exe (out)\r\n" + program,
		tbsRuleIn:  "Rule Name: K2F PURGE - Block tbs_browser.exe (in)\r\n" + program,
	}}
	withProgramRunner(t, rec)
	exe := `C:\Games\NIKKE\Launcher\intl_service\tbs_browser.exe`
	p := Plan(nil, []string{"89.127.233.127"})
	p.UseHosts = false
	p.FlushDNS = false
	p.BlockTBSBrowser = true
	p.ProgramPaths = []string{exe}
	st, err := Apply(context.Background(), p, func(model.Progress) {})
	if err != nil {
		t.Fatal(err)
	}
	sawOut, sawIn := false, false
	for _, r := range st.Rules {
		if r.Name == tbsRuleOut {
			sawOut = true
		}
		if r.Name == tbsRuleIn {
			sawIn = true
		}
	}
	if !sawOut || !sawIn {
		t.Fatalf("program rules missing from status: %+v", st.Rules)
	}
}
