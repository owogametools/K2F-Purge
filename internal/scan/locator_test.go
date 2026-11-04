package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestDiscoverWindowsLauncher(t *testing.T) {
	root, p := fixturePaths(t, "windows")
	data := filepath.Join(p.AppData, "nikke_launcher")
	mustWrite(t, filepath.Join(data, "tbs_cache", "Local Storage", "leveldb", "CURRENT"), "1\n")
	install := filepath.Join(p.UserProfile, "Games", "NIKKE")
	mustWrite(t, filepath.Join(install, "Launcher", "intl_service", "debug.log"), "FETCH_LIST suc success\n")

	targets := DiscoverTargets(p, model.ScanOptions{})
	if !hasTarget(targets, model.TargetLauncherData, data) {
		t.Fatalf("missing launcher-data: %+v", targets)
	}
	if !hasTarget(targets, model.TargetLauncherInstall, install) {
		t.Fatalf("missing install: %+v", targets)
	}
	_ = root
}

func TestDiscoverExtraDirs(t *testing.T) {
	_, p := fixturePaths(t, "linux")
	extra := filepath.Join(p.Home, "custom-launcher")
	mustWrite(t, filepath.Join(extra, "intl_service", "debug.log"), "ok\n")
	targets := DiscoverTargets(p, model.ScanOptions{ExtraLauncherDirs: []string{extra}})
	if !hasTarget(targets, model.TargetLauncherInstall, extra) {
		t.Fatalf("missing extra install: %+v", targets)
	}
}

func TestDiscoverWinePrefix(t *testing.T) {
	_, p := fixturePaths(t, "linux")
	pfx := filepath.Join(p.Home, ".steam", "steam", "steamapps", "compatdata", "1234", "pfx")
	data := filepath.Join(pfx, "drive_c", "users", "steamuser", "AppData", "Roaming", "nikke_launcher")
	mustWrite(t, filepath.Join(data, "tbs_cache", "Local Storage", "leveldb", "CURRENT"), "1\n")
	mustWrite(t, filepath.Join(pfx, "system.reg"), "WINE\n")
	if err := os.MkdirAll(filepath.Join(pfx, "drive_c"), 0o755); err != nil {
		t.Fatal(err)
	}
	targets := DiscoverTargets(p, model.ScanOptions{})
	if !hasTarget(targets, model.TargetWinePrefix, pfx) {
		t.Fatalf("missing prefix: %+v", targets)
	}
	if !hasTarget(targets, model.TargetLauncherData, data) {
		t.Fatalf("missing data in prefix: %+v", targets)
	}
}

func TestDiscoverDoesNotUseLiveEnv(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only live env check")
	}
	_, p := fixturePaths(t, "windows")
	targets := DiscoverTargets(p, model.ScanOptions{})
	realApp := os.Getenv("APPDATA")
	for _, tg := range targets {
		if realApp != "" && filepath.VolumeName(tg.Path) == filepath.VolumeName(realApp) {
			if len(tg.Path) >= len(realApp) && filepath.Clean(tg.Path)[:len(filepath.Clean(realApp))] == filepath.Clean(realApp) {
				t.Fatalf("touched live APPDATA %s", tg.Path)
			}
		}
	}
}

func hasTarget(targets []model.ScanTarget, kind, path string) bool {
	path = filepath.Clean(path)
	for _, t := range targets {
		if t.Kind == kind && filepath.Clean(t.Path) == path && t.Exists {
			return true
		}
	}
	return false
}
