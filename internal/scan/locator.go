// Package scan locates NIKKE launcher artefacts and matches them against IOC rules.
package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/owogametools/k2f-purge/internal/model"
)

const installSearchDepth = 3

// Paths is a snapshot of the places the locator should look.
// Tests inject a fake tree; production uses DefaultPaths.
type Paths struct {
	AppData      string
	LocalAppData string
	Home         string
	Temp         string
	SystemRoot   string
	UserProfile  string
	GOOS         string
}

// DefaultPaths reads the live process environment.
func DefaultPaths() Paths {
	home, _ := os.UserHomeDir()
	p := Paths{
		AppData:      os.Getenv("APPDATA"),
		LocalAppData: os.Getenv("LOCALAPPDATA"),
		Home:         home,
		Temp:         os.TempDir(),
		SystemRoot:   os.Getenv("SystemRoot"),
		UserProfile:  os.Getenv("USERPROFILE"),
		GOOS:         runtime.GOOS,
	}
	if p.UserProfile == "" {
		p.UserProfile = home
	}
	return p
}

// DiscoverTargets lists the roots a scan will inspect. It does not walk the
// whole disk: only known launcher, Chrome helper, temp, and Wine/Proton paths.
func DiscoverTargets(p Paths, opts model.ScanOptions) []model.ScanTarget {
	if p.GOOS == "" {
		p.GOOS = runtime.GOOS
	}
	seen := map[string]struct{}{}
	var out []model.ScanTarget
	add := func(kind, path, note string) {
		path = filepath.Clean(path)
		if path == "" || path == "." {
			return
		}
		key := kind + "\x00" + strings.ToLower(filepath.ToSlash(path))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		st, err := os.Lstat(path)
		exists := err == nil && st != nil
		out = append(out, model.ScanTarget{
			ID:     kind + ":" + filepath.ToSlash(path),
			Kind:   kind,
			Path:   path,
			Exists: exists,
			Note:   note,
		})
	}

	if p.GOOS == "windows" {
		discoverWindows(p, add)
	} else {
		discoverUnix(p, add)
	}

	for _, extra := range opts.ExtraLauncherDirs {
		extra = filepath.Clean(extra)
		if extra == "" || extra == "." {
			continue
		}
		switch {
		case isWinePrefix(extra):
			add(model.TargetWinePrefix, extra, "user-supplied prefix")
			discoverInsidePrefix(extra, add)
		case isLauncherInstall(extra):
			add(model.TargetLauncherInstall, extra, "user-supplied install")
		default:
			add(model.TargetLauncherData, extra, "user-supplied launcher path")
			if inner := filepath.Join(extra, "Launcher"); isLauncherInstall(inner) {
				add(model.TargetLauncherInstall, inner, "user-supplied install")
			}
		}
	}
	for _, extra := range opts.ExtraPrefixes {
		extra = filepath.Clean(extra)
		if extra == "" || extra == "." {
			continue
		}
		add(model.TargetWinePrefix, extra, "user-supplied prefix")
		discoverInsidePrefix(extra, add)
	}

	if p.Temp != "" {
		add(model.TargetTemp, p.Temp, "system temp")
	}
	return out
}

func discoverWindows(p Paths, add func(kind, path, note string)) {
	if p.AppData != "" {
		add(model.TargetLauncherData, filepath.Join(p.AppData, "nikke_launcher"), "Roaming nikke_launcher")
		add(model.TargetLauncherData, filepath.Join(p.AppData, "nikke_launcher_hmt"), "Roaming nikke_launcher_hmt")
	}
	if p.LocalAppData != "" {
		chromeData := filepath.Join(p.LocalAppData, "Google", "Chrome", "User Data")
		add(model.TargetChromeProfile, chromeData, "Chrome user data")
		add(model.TargetChromeHelper, filepath.Join(chromeData, "PlatformExperienceHelper"), "Chrome PlatformExperienceHelper")
		for _, rel := range []string{
			filepath.Join("Microsoft", "Edge", "User Data"),
			filepath.Join("BraveSoftware", "Brave-Browser", "User Data"),
			filepath.Join("Vivaldi", "User Data"),
			filepath.Join("Opera Software", "Opera Stable"),
		} {
			add(model.TargetChromeProfile, filepath.Join(p.LocalAppData, rel), "browser profile")
		}
	}
	for _, root := range windowsSearchRoots(p) {
		for _, install := range findInstalls(root, installSearchDepth) {
			add(model.TargetLauncherInstall, install, "install under "+root)
		}
	}
}

func discoverUnix(p Paths, add func(kind, path, note string)) {
	home := p.Home
	if home == "" {
		return
	}
	for _, pattern := range unixPrefixGlobs(home, p.GOOS) {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if !isWinePrefix(m) {
				continue
			}
			add(model.TargetWinePrefix, m, "wine/proton prefix")
			discoverInsidePrefix(m, add)
		}
	}
	wineHome := filepath.Join(home, ".wine")
	if isWinePrefix(wineHome) {
		add(model.TargetWinePrefix, wineHome, "default wine prefix")
		discoverInsidePrefix(wineHome, add)
	}
}

func unixPrefixGlobs(home, goos string) []string {
	globs := []string{
		filepath.Join(home, ".steam", "steam", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".steam", "root", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".local", "share", "Steam", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".local", "share", "steam", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".local", "share", "wineprefixes", "*"),
		filepath.Join(home, ".local", "share", "bottles", "bottles", "*"),
		filepath.Join(home, ".cxoffice", "*"),
		filepath.Join(home, "Games", "Heroic", "Prefixes", "*"),
	}
	if goos == "darwin" {
		globs = append(globs,
			filepath.Join(home, "Library", "Application Support", "Steam", "steamapps", "compatdata", "*", "pfx"),
			filepath.Join(home, "Library", "Application Support", "CrossOver", "Bottles", "*"),
			filepath.Join(home, "Library", "Containers", "com.isaacmarovitz.Whisky", "Bottles", "*"),
		)
	}
	return globs
}

func discoverInsidePrefix(pfx string, add func(kind, path, note string)) {
	users := filepath.Join(pfx, "drive_c", "users")
	entries, err := os.ReadDir(users)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			roaming := filepath.Join(users, e.Name(), "AppData", "Roaming")
			for _, name := range []string{"nikke_launcher", "nikke_launcher_hmt"} {
				add(model.TargetLauncherData, filepath.Join(roaming, name), "prefix "+filepath.Base(e.Name()))
			}
		}
	}
	for _, root := range []string{
		filepath.Join(pfx, "drive_c", "Program Files"),
		filepath.Join(pfx, "drive_c", "Program Files (x86)"),
		filepath.Join(pfx, "drive_c", "Games"),
	} {
		for _, install := range findInstalls(root, installSearchDepth) {
			add(model.TargetLauncherInstall, install, "install in prefix")
		}
	}
}

func windowsSearchRoots(p Paths) []string {
	var roots []string
	if p.SystemRoot != "" {
		parent := filepath.Dir(p.SystemRoot)
		roots = append(roots,
			filepath.Join(parent, "Program Files"),
			filepath.Join(parent, "Program Files (x86)"),
			filepath.Join(parent, "Games"),
		)
	}
	if p.UserProfile != "" {
		roots = append(roots, filepath.Join(p.UserProfile, "Games"))
	}
	// Live Windows: other drive letters' Games / NIKKE* folders.
	// Skip when SystemRoot is a fixture so tests never touch the real disk.
	if runtime.GOOS == "windows" && p.GOOS == "windows" && p.SystemRoot != "" &&
		strings.EqualFold(p.SystemRoot, os.Getenv("SystemRoot")) {
		vol := filepath.VolumeName(p.SystemRoot)
		if vol != "" {
			roots = append(roots, filepath.Join(vol+string(os.PathSeparator), "Games"))
		}
		for c := 'D'; c <= 'Z'; c++ {
			drive := string(c) + `:\`
			if _, err := os.Lstat(drive); err != nil {
				continue
			}
			roots = append(roots, filepath.Join(drive, "Games"))
			matches, _ := filepath.Glob(filepath.Join(drive, "NIKKE*"))
			roots = append(roots, matches...)
		}
	}
	return roots
}

func findInstalls(root string, maxDepth int) []string {
	st, err := os.Lstat(root)
	if err != nil || !st.IsDir() {
		return nil
	}
	var found []string
	var walk func(string, int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}
		if isLauncherInstall(dir) {
			found = append(found, dir)
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if skipInstallName(name) {
				continue
			}
			if depth == 0 && !interestingInstallName(name) {
				continue
			}
			walk(filepath.Join(dir, name), depth+1)
		}
	}
	walk(root, 0)
	return found
}

func skipInstallName(name string) bool {
	l := strings.ToLower(name)
	switch l {
	case "windows", "system32", "syswow64", "$recycle.bin", "node_modules", ".git":
		return true
	}
	return false
}

func interestingInstallName(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "nikke") ||
		strings.Contains(l, "levelinfinite") ||
		strings.Contains(l, "godlike") ||
		l == "games" ||
		strings.Contains(l, "launcher")
}

func isLauncherInstall(path string) bool {
	for _, rel := range []string{
		filepath.Join("intl_service", "debug.log"),
		filepath.Join("Launcher", "intl_service", "debug.log"),
		filepath.Join("log", "tinyget"),
		filepath.Join("Launcher", "log"),
	} {
		if _, err := os.Lstat(filepath.Join(path, rel)); err == nil {
			return true
		}
	}
	return false
}

func isWinePrefix(path string) bool {
	if st, err := os.Lstat(filepath.Join(path, "drive_c")); err == nil && st.IsDir() {
		return true
	}
	if _, err := os.Lstat(filepath.Join(path, "system.reg")); err == nil {
		return true
	}
	return false
}
