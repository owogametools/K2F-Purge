package clean

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/owogametools/k2f-purge/internal/model"
)

var (
	errHKLM           = errors.New("refusing to touch HKEY_LOCAL_MACHINE")
	errHelperParent   = errors.New("refusing to delete PlatformExperienceHelper parent folder")
	errNotAllowlisted = errors.New("path is not under an allowlisted root")
	errSymlinkEscape  = errors.New("symlink escapes allowlisted root")
	errBadRegistry    = errors.New("registry key is not the allowlisted HKCU CLSID")
)

const k2fCLSID = `{E77CC89B-7401-4C04-8CED-149DB35ADD04}`

var allowedCLSIDKey = strings.ToUpper(`HKCU\Software\Classes\CLSID\` + k2fCLSID)
var allowedCLSIDKeyLong = strings.ToUpper(`HKEY_CURRENT_USER\Software\Classes\CLSID\` + k2fCLSID)

func isRegistryPath(p string) bool {
	u := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(p), "/", `\`))
	return strings.HasPrefix(u, "HKCU\\") ||
		strings.HasPrefix(u, "HKLM\\") ||
		strings.HasPrefix(u, "HKU\\") ||
		strings.HasPrefix(u, "HKCR\\") ||
		strings.HasPrefix(u, "HKEY_")
}

func isForbiddenHive(p string) bool {
	u := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(p), "/", `\`))
	switch {
	case strings.HasPrefix(u, "HKLM"), strings.HasPrefix(u, "HKEY_LOCAL_MACHINE"):
		return true
	case strings.HasPrefix(u, "HKU\\"), strings.HasPrefix(u, "HKEY_USERS"):
		return true
	case strings.HasPrefix(u, "HKCR\\"), strings.HasPrefix(u, "HKEY_CLASSES_ROOT"):
		return true
	case strings.HasPrefix(u, "HKCC\\"), strings.HasPrefix(u, "HKEY_CURRENT_CONFIG"):
		return true
	default:
		return false
	}
}

func allowedRegistryKey(key string) error {
	if isForbiddenHive(key) {
		return errHKLM
	}
	n := normalizeReg(key)
	if n != allowedCLSIDKey && n != allowedCLSIDKeyLong &&
		!strings.HasPrefix(n, allowedCLSIDKey+`\`) &&
		!strings.HasPrefix(n, allowedCLSIDKeyLong+`\`) {
		return errBadRegistry
	}
	for _, r := range key {
		if r == ';' || r == '&' || r == '|' || r == '\n' || r == '\r' || r == '"' || r == '`' {
			return errBadRegistry
		}
	}
	return nil
}

func normalizeReg(key string) string {
	k := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(key), "/", `\`))
	k = strings.TrimSuffix(k, `\`)
	return k
}

func isHelperParentName(name string) bool {
	return strings.EqualFold(name, "PlatformExperienceHelper")
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !unicode.Is(unicode.ASCII_Hex_Digit, c) {
			return false
		}
	}
	return true
}

func isHelperParent(path string) bool {
	return isHelperParentName(filepath.Base(filepath.Clean(path)))
}

func chromeHelperDir(path string) (string, error) {
	p := filepath.Clean(path)
	base := filepath.Base(p)
	if strings.EqualFold(base, "platform_experience_helper.dll") {
		p = filepath.Dir(p)
		base = filepath.Base(p)
	}
	if isHelperParentName(base) {
		return "", errHelperParent
	}
	if !isHex64(base) {
		return "", fmt.Errorf("not a 64-hex PlatformExperienceHelper folder: %s", p)
	}
	parent := filepath.Base(filepath.Dir(p))
	if !isHelperParentName(parent) {
		return "", fmt.Errorf("64-hex folder not under PlatformExperienceHelper: %s", p)
	}
	return p, nil
}

func leftoverName(name string) bool {
	switch strings.ToLower(name) {
	case "platform_experience_helper.dll.old", "old-clsid.txt", "service_util.dll":
		return true
	default:
		return false
	}
}

func isTempArtifactName(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "k2f-"+"bcreds-") {
		return true
	}
	if strings.HasPrefix(lower, "k2f_screen_") && strings.HasSuffix(lower, ".jpg") {
		return true
	}
	if strings.HasPrefix(lower, "k2f") && strings.HasSuffix(lower, ".lua") {
		return true
	}
	return false
}

func underRoot(path, root string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absPath = filepath.Clean(absPath)
	absRoot = filepath.Clean(absRoot)
	if runtime.GOOS == "windows" {
		absPath = strings.ToLower(absPath)
		absRoot = strings.ToLower(absRoot)
	}
	if absPath == absRoot {
		return true
	}
	sep := string(os.PathSeparator)
	prefix := absRoot
	if !strings.HasSuffix(prefix, sep) {
		prefix += sep
	}
	return strings.HasPrefix(absPath, prefix)
}

func underAny(path string, roots []string) bool {
	for _, r := range roots {
		if r == "" {
			continue
		}
		if underRoot(path, r) {
			return true
		}
	}
	return false
}

func resolveNoEscape(path string, roots []string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if !underAny(abs, roots) {
		return "", fmt.Errorf("%w: %s", errNotAllowlisted, abs)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return abs, nil
		}
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(abs)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(abs), target)
		}
		target = filepath.Clean(target)
		if !underAny(target, roots) {
			return "", fmt.Errorf("%w: %s -> %s", errSymlinkEscape, abs, target)
		}
		return target, nil
	}
	return abs, nil
}

func walkNoEscape(root string, roots []string) error {
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if _, err := resolveNoEscape(p, roots); err != nil {
				return err
			}
		}
		if !underAny(p, roots) {
			return fmt.Errorf("%w: %s", errNotAllowlisted, p)
		}
		return nil
	})
}

func knownRoots() []string {
	var roots []string
	add := func(p string) {
		if p != "" {
			roots = append(roots, p)
		}
	}
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		add(filepath.Join(appdata, "nikke_launcher"))
		add(filepath.Join(appdata, "nikke_launcher_hmt"))
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		add(filepath.Join(local, "Google", "Chrome", "User Data", "PlatformExperienceHelper"))
		add(filepath.Join(local, "Microsoft", "Edge", "User Data", "PlatformExperienceHelper"))
		add(filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data", "PlatformExperienceHelper"))
		add(filepath.Join(local, "Google", "Chrome", "Application"))
		add(filepath.Join(local, "Microsoft", "Edge", "Application"))
	}
	if temp := os.TempDir(); temp != "" {
		add(temp)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		add(filepath.Join(home, ".wine"))
		add(filepath.Join(home, ".local", "share", "wineprefixes"))
		add(filepath.Join(home, ".steam", "steam", "steamapps", "compatdata"))
		add(filepath.Join(home, ".var", "app", "com.valvesoftware.Steam", "data", "Steam", "steamapps", "compatdata"))
		add(filepath.Join(home, "Library", "Application Support", "CrossOver"))
		add(filepath.Join(home, "Library", "Containers", "com.codeweavers.CrossOver", "Data"))
	}
	return roots
}

func collectRoots(scanTargets []string) []string {
	roots := knownRoots()
	for _, t := range scanTargets {
		if t != "" {
			roots = append(roots, t)
		}
	}
	return roots
}

func isWinePath(p string) bool {
	s := strings.ToLower(filepath.ToSlash(p))
	switch {
	case strings.Contains(s, "/drive_c/"),
		strings.Contains(s, "/compatdata/"),
		strings.Contains(s, "/wineprefixes/"),
		strings.Contains(s, "/.wine/"),
		strings.Contains(s, "/pfx/"),
		strings.Contains(s, "/crossover/"),
		strings.Contains(s, "/bottles/"),
		strings.Contains(s, "/lutris/"):
		return true
	default:
		return false
	}
}

// validateItem re-checks an item before any destructive action so a
// crafted CleanPlan cannot point at HKLM, the helper parent, or a
// random path.
func validateItem(it model.CleanItem, roots []string) error {
	if isForbiddenHive(it.Path) {
		return errHKLM
	}
	if isHelperParent(it.Path) {
		return errHelperParent
	}
	switch it.Kind {
	case model.CleanRegistryCLSID:
		return allowedRegistryKey(it.Path)
	case model.CleanChromeHelper:
		if _, err := chromeHelperDir(it.Path); err != nil {
			return err
		}
	case model.CleanChromeLeftover:
		if !leftoverName(filepath.Base(it.Path)) {
			return fmt.Errorf("not an allowed leftover name: %s", it.Path)
		}
	case model.CleanLauncherCache:
		if findNamedAncestor(it.Path, "tbs_cache") == "" {
			return fmt.Errorf("not a tbs_cache path: %s", it.Path)
		}
	case model.CleanTinygetPayload:
		base := strings.ToLower(filepath.Base(it.Path))
		if findNamedAncestor(it.Path, "tinyget") == "" &&
			!strings.Contains(base, "tinyget") &&
			!(strings.HasPrefix(base, "k2f") && strings.HasSuffix(base, ".lua")) {
			return fmt.Errorf("not a tinyget path: %s", it.Path)
		}
	case model.CleanTempArtifacts:
		if !isTempArtifactName(filepath.Base(it.Path)) {
			return fmt.Errorf("not a temp artifact name: %s", it.Path)
		}
	case model.CleanWineArtifact:
		if !isWinePath(it.Path) && !isTempArtifactName(filepath.Base(it.Path)) {
			return fmt.Errorf("not a wine artifact: %s", it.Path)
		}
	default:
		return fmt.Errorf("unknown clean kind %q", it.Kind)
	}
	if isRegistryPath(it.Path) {
		return nil
	}
	if underAny(it.Path, roots) || extraAllowed(it) {
		return nil
	}
	return fmt.Errorf("%w: %s", errNotAllowlisted, it.Path)
}

func extraAllowed(it model.CleanItem) bool {
	p := it.Path
	switch it.Kind {
	case model.CleanChromeHelper:
		_, err := chromeHelperDir(p)
		return err == nil
	case model.CleanLauncherCache, model.CleanTinygetPayload:
		return findNamedAncestor(p, "nikke_launcher") != "" ||
			findNamedAncestor(p, "nikke_launcher_hmt") != "" ||
			isWinePath(p)
	case model.CleanWineArtifact:
		return isWinePath(p)
	case model.CleanTempArtifacts:
		return underRoot(p, os.TempDir())
	case model.CleanChromeLeftover:
		s := strings.ToLower(filepath.ToSlash(p))
		return leftoverName(filepath.Base(p)) && !isHelperParent(p) &&
			(strings.Contains(s, "/platformexperiencehelper/") ||
				strings.Contains(s, "/chrome/application/") ||
				strings.Contains(s, "/edge/application/"))
	default:
		return false
	}
}
