package clean

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestManifestRoundTripRestore(t *testing.T) {
	qroot := withQuarantine(t)
	srcDir := t.TempDir()
	name := "k2f-" + "bcreds-1"
	src := filepath.Join(srcDir, name)
	if err := os.WriteFile(src, []byte("hello-k2f"), 0o600); err != nil {
		t.Fatal(err)
	}

	scan := &model.ScanResult{
		ID: "s1",
		Targets: []model.ScanTarget{
			{ID: "tmp", Kind: model.TargetTemp, Path: srcDir, Exists: true},
		},
		Findings: []model.Finding{
			{RuleID: "temp.k2f_files", Path: src, Title: "temp"},
		},
	}
	plan, err := Plan(scan)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 1 {
		t.Fatalf("items=%v warnings=%v", plan.Items, plan.Warnings)
	}

	res, err := Apply(context.Background(), plan, nil, model.CleanQuarantine, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 1 {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	list, err := QuarantineList()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list %+v (qroot=%s)", list, qroot)
	}
	if list[0].SHA256 == "" || list[0].OriginalPath == "" {
		t.Fatalf("incomplete entry %+v", list[0])
	}

	if err := Restore(context.Background(), []string{list[0].ID}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello-k2f" {
		t.Fatalf("restored %q", data)
	}
}

func TestQuarantinePurge(t *testing.T) {
	withQuarantine(t)
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "k2f_screen_1.jpg")
	if err := os.WriteFile(src, []byte("jpg"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(&model.ScanResult{
		Targets:  []model.ScanTarget{{Path: srcDir, Exists: true, Kind: model.TargetTemp}},
		Findings: []model.Finding{{RuleID: "temp.k2f_files", Path: src}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), plan, []string{plan.Items[0].ID}, model.CleanQuarantine, nil); err != nil {
		t.Fatal(err)
	}
	list, err := QuarantineList()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list %v", list)
	}
	if err := Purge(context.Background(), []string{list[0].ID}); err != nil {
		t.Fatal(err)
	}
	list, err = QuarantineList()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("still listed: %v", list)
	}
	if err := Restore(context.Background(), []string{"nope"}); err == nil {
		t.Fatal("restore of missing id should fail")
	}
}

func TestQuarantineRootRequiresOverrideInTests(t *testing.T) {
	quarantineOverride = ""
	if _, err := QuarantineRoot(); err == nil {
		t.Fatal("expected error")
	}
}

func TestDirQuarantineRoundTrip(t *testing.T) {
	withQuarantine(t)
	srcDir := t.TempDir()
	cache := filepath.Join(srcDir, "nikke_launcher", "tbs_cache")
	if err := os.MkdirAll(filepath.Join(cache, "Code Cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cache, "Code Cache", "js")
	if err := os.MkdirAll(f, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f, "x"), []byte("cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(&model.ScanResult{
		Targets: []model.ScanTarget{{Path: srcDir, Exists: true, Kind: model.TargetLauncherData}},
		Findings: []model.Finding{
			{RuleID: "state.k2f_agent", Path: filepath.Join(cache, "Local Storage", "leveldb", "x")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 1 || plan.Items[0].Kind != model.CleanLauncherCache {
		t.Fatalf("plan %+v warnings %v", plan.Items, plan.Warnings)
	}
	res, err := Apply(context.Background(), plan, nil, model.CleanQuarantine, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Quarantined != 1 {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("cache still there: %v", err)
	}
	list, _ := QuarantineList()
	if err := Restore(context.Background(), []string{list[0].ID}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(f, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "cache" {
		t.Fatalf("got %q", got)
	}
}
