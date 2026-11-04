package clean

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestPlanRejectsOutsideAllowlistHKLMAndHelperParent(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "k2f-"+"bcreds-aaa")
	if err := os.WriteFile(inside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	helperParent := filepath.Join(root, "PlatformExperienceHelper")
	if err := os.MkdirAll(helperParent, 0o700); err != nil {
		t.Fatal(err)
	}
	hex := strings.Repeat("ab", 32)
	helperChild := filepath.Join(helperParent, hex)
	if err := os.MkdirAll(helperChild, 0o700); err != nil {
		t.Fatal(err)
	}
	dll := filepath.Join(helperChild, "platform_experience_helper.dll")
	if err := os.WriteFile(dll, []byte("mz"), 0o600); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(`C:\Windows\System32`, "notepad.exe")
	if runtime.GOOS != "windows" {
		outside = "/etc/passwd"
	}

	scan := &model.ScanResult{
		ID: "s1",
		Targets: []model.ScanTarget{
			{ID: "tmp", Kind: model.TargetTemp, Path: root, Exists: true},
		},
		Findings: []model.Finding{
			{RuleID: "temp.k2f_files", Path: inside, Title: "temp"},
			{RuleID: "temp.k2f_files", Path: outside, Title: "outside"},
			{RuleID: "reg.clsid_hkcu", Path: `HKLM\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`},
			{RuleID: "reg.clsid_hkcu", Path: `HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`},
			{RuleID: "chrome.helper_dll", Path: helperParent},
			{RuleID: "chrome.helper_dll", Path: dll},
			{RuleID: "reg.clsid_hkcu", Path: `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`},
		},
	}
	plan, err := Plan(scan)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, it := range plan.Items {
		if isRegistryPath(it.Path) && isForbiddenHive(it.Path) {
			t.Fatalf("unsafe registry item leaked into plan: %+v", it)
		}
		if it.Path == outside {
			t.Fatalf("outside path leaked into plan: %+v", it)
		}
		if isHelperParent(it.Path) {
			t.Fatalf("helper parent in plan: %+v", it)
		}
		kinds[it.Kind]++
	}
	if kinds[model.CleanTempArtifacts] != 1 {
		t.Fatalf("expected one temp item, kinds=%v items=%v warnings=%v", kinds, plan.Items, plan.Warnings)
	}
	if kinds[model.CleanChromeHelper] != 1 {
		t.Fatalf("expected one helper item, kinds=%v warnings=%v", kinds, plan.Warnings)
	}
	if kinds[model.CleanRegistryCLSID] != 1 {
		t.Fatalf("expected one HKCU registry item, kinds=%v warnings=%v", kinds, plan.Warnings)
	}
	joined := strings.Join(plan.Warnings, "\n")
	if !strings.Contains(joined, "HKLM") && !strings.Contains(strings.ToUpper(joined), "HKEY_LOCAL_MACHINE") {
		t.Fatalf("expected HKLM warning, got %v", plan.Warnings)
	}
	if !strings.Contains(strings.ToLower(joined), "platformexperiencehelper") && !strings.Contains(joined, "parent") {
		t.Fatalf("expected helper parent warning, got %v", plan.Warnings)
	}
}

func TestApplyRefusesCraftedPlan(t *testing.T) {
	withQuarantine(t)
	outside := filepath.Join(`C:\Windows`, "notepad.exe")
	if runtime.GOOS != "windows" {
		outside = "/etc/passwd"
	}
	plan := &model.CleanPlan{Items: []model.CleanItem{
		{ID: "bad", Kind: model.CleanTempArtifacts, Path: outside, RuleID: "temp.k2f_files"},
		{ID: "hlm", Kind: model.CleanRegistryCLSID, Path: `HKLM\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`},
		{ID: "par", Kind: model.CleanChromeHelper, Path: filepath.Join(t.TempDir(), "PlatformExperienceHelper")},
	}}
	res, err := Apply(context.Background(), plan, nil, model.CleanQuarantine, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 0 || res.Deleted != 0 {
		t.Fatalf("must not clean unsafe items: %+v", res)
	}
	if len(res.Failures) < 3 {
		t.Fatalf("expected failures, got %+v", res)
	}
}

func TestValidateItemHKLM(t *testing.T) {
	err := validateItem(model.CleanItem{
		Kind: model.CleanRegistryCLSID,
		Path: `HKLM\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`,
	}, nil)
	if !errors.Is(err, errHKLM) {
		t.Fatalf("got %v", err)
	}
}

func withQuarantine(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "q")
	quarantineOverride = dir
	t.Cleanup(func() { quarantineOverride = "" })
	return dir
}
