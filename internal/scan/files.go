package scan

import (
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/owogametools/k2f-purge/internal/model"
)

const maxFilesPerScope = 8192

type fileRef struct {
	path   string
	scopes []string
}

func collectFiles(targets []model.ScanTarget, goos string) (files []fileRef, limitations []string) {
	index := map[string]*fileRef{}
	add := func(path string, scope string) {
		path = filepath.Clean(path)
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() {
			return
		}
		if existing, ok := index[path]; ok {
			if !hasScope(existing.scopes, scope) {
				existing.scopes = append(existing.scopes, scope)
			}
			return
		}
		index[path] = &fileRef{path: path, scopes: []string{scope}}
	}

	counts := map[string]int{}
	addCapped := func(path, scope string) {
		if counts[scope] >= maxFilesPerScope {
			return
		}
		before := len(index)
		add(path, scope)
		if len(index) > before {
			counts[scope]++
			if counts[scope] == maxFilesPerScope {
				limitations = append(limitations, "file cap reached for scope "+scope)
			}
		}
	}

	for _, t := range targets {
		if !t.Exists {
			continue
		}
		switch t.Kind {
		case model.TargetLauncherData, model.TargetLauncherInstall, model.TargetWinePrefix:
			collectLauncherTree(t.Path, addCapped)
		case model.TargetTemp:
			collectTemp(t.Path, addCapped)
		case model.TargetChromeHelper, model.TargetChromeProfile:
			if goos == "windows" {
				collectChrome(t.Path, addCapped)
			}
		}
	}

	files = make([]fileRef, 0, len(index))
	for _, ref := range index {
		files = append(files, *ref)
	}
	return files, limitations
}

func collectLauncherTree(root string, add func(path, scope string)) {
	for _, rel := range []string{
		filepath.Join("intl_service", "debug.log"),
		filepath.Join("Launcher", "intl_service", "debug.log"),
	} {
		add(filepath.Join(root, rel), "launcher-log")
	}
	for _, rel := range []string{
		filepath.Join("log", "tinyget.mem.log"),
		filepath.Join("Launcher", "log", "tinyget.mem.log"),
	} {
		add(filepath.Join(root, rel), "tinyget-log")
	}
	for _, rel := range []string{
		filepath.Join("log", "tinyget"),
		filepath.Join("Launcher", "log", "tinyget"),
	} {
		listDir(filepath.Join(root, rel), func(name string) bool {
			l := strings.ToLower(name)
			return strings.HasSuffix(l, ".log") || strings.HasSuffix(l, ".lua") ||
				strings.Contains(l, "tinyget") || strings.HasPrefix(l, "k2f")
		}, func(path string) { add(path, "tinyget-log") })
	}
	listDir(filepath.Join(root, "tbs_cache", "Local Storage", "leveldb"), isLevelDBName, func(path string) {
		add(path, "leveldb")
	})
	listDir(filepath.Join(root, "tbs_cache", "Code Cache", "js"), func(string) bool { return true }, func(path string) {
		add(path, "code-cache")
		add(path, "tbs-cache")
	})
	for _, rel := range []string{
		filepath.Join("tbs_cache", "Cache"),
		filepath.Join("tbs_cache", "Cache", "Cache_Data"),
	} {
		listDir(filepath.Join(root, rel), isHTTPCacheName, func(path string) {
			add(path, "http-cache")
			add(path, "tbs-cache")
		})
	}
	listDir(filepath.Join(root, "log"), func(name string) bool {
		l := strings.ToLower(name)
		return strings.HasPrefix(l, "k2f") && strings.HasSuffix(l, ".lua")
	}, func(path string) { add(path, "tinyget-log") })
	listDir(root, func(name string) bool {
		l := strings.ToLower(name)
		return strings.HasSuffix(l, ".js") || strings.HasSuffix(l, ".lua")
	}, func(path string) { add(path, "any") })
}

func collectTemp(dir string, add func(path, scope string)) {
	listDir(dir, func(name string) bool {
		l := strings.ToLower(name)
		return strings.HasPrefix(l, "k2f-") || strings.HasPrefix(l, "k2f_")
	}, func(path string) { add(path, "temp") })
}

func collectChrome(root string, add func(path, scope string)) {
	if strings.EqualFold(filepath.Base(root), "PlatformExperienceHelper") {
		listDir(root, isLeftoverName, func(path string) { add(path, "chrome-leftover") })
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || !isHex64(e.Name()) {
				continue
			}
			add(filepath.Join(root, e.Name(), "platform_experience_helper.dll"), "chrome-helper")
		}
		return
	}
	helper := filepath.Join(root, "PlatformExperienceHelper")
	if st, err := os.Lstat(helper); err == nil && st.IsDir() {
		collectChrome(helper, add)
	}
	if strings.Contains(strings.ToLower(root), "chrome") {
		listDir(filepath.Join(root, "Application"), isLeftoverName, func(path string) { add(path, "chrome-leftover") })
		listDir(root, isLeftoverName, func(path string) { add(path, "chrome-leftover") })
	}
}

func listDir(dir string, want func(name string) bool, add func(path string)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if want != nil && !want(e.Name()) {
			continue
		}
		add(filepath.Join(dir, e.Name()))
	}
}

func isLevelDBName(name string) bool {
	l := strings.ToLower(name)
	switch {
	case l == "current", l == "log", l == "log.old":
		return true
	case strings.HasPrefix(l, "manifest-"):
		return true
	case strings.HasSuffix(l, ".ldb"), strings.HasSuffix(l, ".log"), strings.HasSuffix(l, ".sst"):
		return true
	}
	return false
}

func isHTTPCacheName(name string) bool {
	l := strings.ToLower(name)
	return strings.HasPrefix(l, "data_") || strings.HasPrefix(l, "f_")
}

func isLeftoverName(name string) bool {
	l := strings.ToLower(name)
	return l == "platform_experience_helper.dll.old" || l == "old-clsid.txt" || l == "service_util.dll"
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return false
		}
	}
	return true
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
