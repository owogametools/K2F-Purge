package exposure

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

// Env is the resolution context. Tests inject GOOS, home and environment.
type Env struct {
	GOOS       string
	Home       string
	Lookup     func(string) string
	AbsRoot    string // if set, C:\ is remapped here (tests / ScanWithHome)
	WinePrefix string
	WineUser   string
	// HostOS is the OS whose filesystem holds the paths. Inside a Wine
	// prefix on Linux or macOS the variables are Windows ones (GOOS stays
	// "windows") but the separators must be the host's.
	HostOS string
}

func (e Env) hostOS() string {
	if e.HostOS != "" {
		return e.HostOS
	}
	return e.GOOS
}

// Resolved is one catalog path after OS / env / glob-prefix mapping.
type Resolved struct {
	Path       string
	MissingVar string
	Note       string
	Skip       bool
}

func (e Env) getenv(name string) string {
	if e.Lookup != nil {
		if v := e.Lookup(name); v != "" {
			return v
		}
		if v := e.Lookup(strings.ToUpper(name)); v != "" {
			return v
		}
		if v := e.Lookup(strings.ToLower(name)); v != "" {
			return v
		}
	}
	return ""
}

func (e Env) sep() string {
	if e.hostOS() == "windows" {
		return `\`
	}
	return `/`
}

func (e Env) toSep(s string) string {
	if e.hostOS() == "windows" {
		return strings.ReplaceAll(s, `/`, `\`)
	}
	return strings.ReplaceAll(s, `\`, `/`)
}

func (e Env) join(elem ...string) string {
	if len(elem) == 0 {
		return ""
	}
	sep := e.sep()
	var b strings.Builder
	for i, s := range elem {
		s = e.toSep(s)
		if i == 0 {
			if s == `/` || s == `\` {
				b.WriteString(sep)
				continue
			}
			b.WriteString(strings.TrimRight(s, `\/`))
			continue
		}
		s = strings.Trim(s, `\/`)
		if s == "" {
			continue
		}
		prev := b.String()
		if prev != "" && !strings.HasSuffix(prev, sep) {
			b.WriteString(sep)
		}
		b.WriteString(s)
	}
	return b.String()
}

func (e Env) wineUserHome() string {
	if e.WinePrefix == "" {
		return e.Home
	}
	user := e.WineUser
	if user == "" {
		user = "steamuser"
	}
	return e.join(e.WinePrefix, "drive_c", "users", user)
}

func (e Env) mapped(name string) string {
	up := strings.ToUpper(name)
	switch up {
	case "HOME", "USERPROFILE":
		if e.WinePrefix != "" {
			return e.wineUserHome()
		}
		if e.Home != "" {
			return e.Home
		}
		return e.getenv(name)
	case "APPDATA":
		if e.WinePrefix != "" {
			return e.join(e.wineUserHome(), "AppData", "Roaming")
		}
		switch e.GOOS {
		case "windows":
			if v := e.getenv("APPDATA"); v != "" {
				return v
			}
			return e.join(e.Home, "AppData", "Roaming")
		case "darwin":
			if v := e.getenv("APPDATA"); v != "" {
				return v
			}
			return e.join(e.Home, "Library", "Application Support")
		default:
			if v := e.getenv("XDG_CONFIG_HOME"); v != "" {
				return v
			}
			return e.join(e.Home, ".config")
		}
	case "LOCALAPPDATA":
		if e.WinePrefix != "" {
			return e.join(e.wineUserHome(), "AppData", "Local")
		}
		switch e.GOOS {
		case "windows":
			if v := e.getenv("LOCALAPPDATA"); v != "" {
				return v
			}
			return e.join(e.Home, "AppData", "Local")
		case "darwin":
			if v := e.getenv("LOCALAPPDATA"); v != "" {
				return v
			}
			return e.join(e.Home, "Library", "Application Support")
		default:
			if v := e.getenv("XDG_DATA_HOME"); v != "" {
				return v
			}
			return e.join(e.Home, ".local", "share")
		}
	case "PROGRAMDATA":
		if e.WinePrefix != "" {
			return e.join(e.WinePrefix, "drive_c", "ProgramData")
		}
		if e.GOOS == "windows" {
			if v := e.getenv("PROGRAMDATA"); v != "" {
				return v
			}
			return e.join(windowsDrive(e), "ProgramData")
		}
		return "/var/lib"
	case "PROGRAMFILES":
		if e.WinePrefix != "" {
			return e.join(e.WinePrefix, "drive_c", "Program Files")
		}
		if e.GOOS == "windows" {
			if v := e.getenv("PROGRAMFILES"); v != "" {
				return v
			}
			return e.join(windowsDrive(e), "Program Files")
		}
		if e.GOOS == "darwin" {
			return "/Applications"
		}
		return "/usr"
	case "TEMP", "TMP":
		if e.WinePrefix != "" {
			return e.join(e.wineUserHome(), "AppData", "Local", "Temp")
		}
		if e.GOOS == "windows" {
			if v := e.getenv("TEMP"); v != "" {
				return v
			}
			if v := e.getenv("TMP"); v != "" {
				return v
			}
			return e.join(e.Home, "AppData", "Local", "Temp")
		}
		if v := e.getenv("TMPDIR"); v != "" {
			return v
		}
		if e.Home != "" {
			return e.join(e.Home, "tmp")
		}
		return "/tmp"
	case "XDG_CONFIG_HOME":
		if v := e.getenv("XDG_CONFIG_HOME"); v != "" {
			return v
		}
		if e.GOOS == "darwin" {
			return e.join(e.Home, "Library", "Application Support")
		}
		return e.join(e.Home, ".config")
	case "XDG_DATA_HOME":
		if v := e.getenv("XDG_DATA_HOME"); v != "" {
			return v
		}
		if e.GOOS == "darwin" {
			return e.join(e.Home, "Library", "Application Support")
		}
		return e.join(e.Home, ".local", "share")
	default:
		return e.getenv(name)
	}
}

func windowsDrive(e Env) string {
	if e.AbsRoot != "" {
		return e.AbsRoot
	}
	return `C:`
}

func (e Env) lookupMapped(name string) (string, bool) {
	up := strings.ToUpper(name)
	switch up {
	case "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
		"PROGRAMDATA", "PROGRAMFILES", "TEMP", "TMP",
		"XDG_CONFIG_HOME", "XDG_DATA_HOME":
		v := e.mapped(up)
		if v == "" {
			return "", false
		}
		return v, true
	default:
		v := e.mapped(name)
		if v == "" {
			return "", false
		}
		return v, true
	}
}

func isEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !unicode.IsLetter(r) && r != '_' {
				return false
			}
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

func expandPercents(env Env, s string) (string, string) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '%' {
			b.WriteByte(s[i])
			i++
			continue
		}
		rest := s[i+1:]
		j := strings.IndexByte(rest, '%')
		if j < 0 {
			b.WriteByte('%')
			i++
			continue
		}
		name := rest[:j]
		if !isEnvName(name) {
			b.WriteByte('%')
			i++
			continue
		}
		val, ok := env.lookupMapped(name)
		if !ok {
			return s, name
		}
		b.WriteString(val)
		i += 1 + j + 1
	}
	return b.String(), ""
}

func expandDollars(env Env, s string) (string, string) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 >= len(s) || !isEnvNameStart(rune(s[i+1])) {
			b.WriteByte('$')
			i++
			continue
		}
		k := i + 1
		for k < len(s) && isEnvNameChar(rune(s[k])) {
			k++
		}
		name := s[i+1 : k]
		val, ok := env.lookupMapped(name)
		if !ok {
			return s, name
		}
		b.WriteString(val)
		i = k
	}
	return b.String(), ""
}

func isEnvNameStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

func isEnvNameChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func isWindowsAbs(s string) bool {
	if len(s) < 3 {
		return false
	}
	if !unicode.IsLetter(rune(s[0])) || s[1] != ':' {
		return false
	}
	return s[2] == '\\' || s[2] == '/'
}

func underHome(env Env, s string) bool {
	if env.Home == "" || s == "" {
		return false
	}
	a := strings.ToLower(strings.ReplaceAll(s, `\`, `/`))
	h := strings.ToLower(strings.ReplaceAll(env.Home, `\`, `/`))
	h = strings.TrimRight(h, `/`)
	return a == h || strings.HasPrefix(a, h+"/")
}

func mapWindowsAbs(env Env, s string) string {
	if underHome(env, s) {
		return env.toSep(s)
	}
	if env.WinePrefix != "" && strings.Contains(strings.ToLower(strings.ReplaceAll(s, `\`, `/`)), "/drive_c/") {
		return env.toSep(s)
	}
	rest := s[2:]
	rest = strings.TrimLeft(rest, `\/`)
	if env.WinePrefix != "" {
		return env.join(env.WinePrefix, "drive_c", rest)
	}
	if env.AbsRoot != "" {
		return env.join(env.AbsRoot, rest)
	}
	if env.GOOS != "windows" {
		return ""
	}
	return env.toSep(s)
}

// ResolvePath maps a catalog path onto env's OS and home. It does not
// touch the filesystem.
func ResolvePath(env Env, raw string) Resolved {
	if env.GOOS == "" {
		env.GOOS = runtime.GOOS
	}
	s := raw
	s, missing := expandPercents(env, s)
	if missing != "" {
		return Resolved{Path: raw, MissingVar: missing, Note: "environment variable not set"}
	}
	s, missing = expandDollars(env, s)
	if missing != "" {
		return Resolved{Path: raw, MissingVar: missing, Note: "environment variable not set"}
	}
	if s == "~" || strings.HasPrefix(s, `~\`) || strings.HasPrefix(s, `~/`) {
		rest := strings.TrimPrefix(s[1:], `\`)
		rest = strings.TrimPrefix(rest, `/`)
		if rest == "" {
			s = env.Home
		} else {
			s = env.join(env.Home, rest)
		}
	}
	if isWindowsAbs(s) {
		mapped := mapWindowsAbs(env, s)
		if mapped == "" {
			return Resolved{Path: raw, Skip: true, Note: "Windows-only path"}
		}
		s = mapped
	}
	s = env.toSep(s)
	return Resolved{Path: s}
}

func liveEnv(home string) Env {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return Env{
		GOOS: runtime.GOOS,
		Home: home,
		Lookup: func(k string) string {
			return os.Getenv(k)
		},
	}
}

func fixtureEnv(goos, home string) Env {
	if goos == "" {
		goos = runtime.GOOS
	}
	abs := filepath.Join(home, "C")
	return Env{
		GOOS:    goos,
		Home:    home,
		AbsRoot: abs,
		Lookup: func(k string) string {
			return fixtureLookup(goos, home, k)
		},
	}
}

func fixtureLookup(goos, home, key string) string {
	up := strings.ToUpper(key)
	switch up {
	case "HOME", "USERPROFILE":
		return home
	case "APPDATA":
		if goos == "windows" {
			return filepath.Join(home, "AppData", "Roaming")
		}
		if goos == "darwin" {
			return filepath.Join(home, "Library", "Application Support")
		}
		return filepath.Join(home, ".config")
	case "LOCALAPPDATA":
		if goos == "windows" {
			return filepath.Join(home, "AppData", "Local")
		}
		if goos == "darwin" {
			return filepath.Join(home, "Library", "Application Support")
		}
		return filepath.Join(home, ".local", "share")
	case "PROGRAMDATA":
		if goos == "windows" {
			return filepath.Join(home, "ProgramData")
		}
		return filepath.Join(home, "var", "lib")
	case "PROGRAMFILES":
		if goos == "windows" {
			return filepath.Join(home, "Program Files")
		}
		return filepath.Join(home, "usr")
	case "TEMP", "TMP", "TMPDIR":
		if goos == "windows" {
			return filepath.Join(home, "AppData", "Local", "Temp")
		}
		return filepath.Join(home, "tmp")
	case "XDG_CONFIG_HOME":
		if goos == "darwin" {
			return filepath.Join(home, "Library", "Application Support")
		}
		return filepath.Join(home, ".config")
	case "XDG_DATA_HOME":
		if goos == "darwin" {
			return filepath.Join(home, "Library", "Application Support")
		}
		return filepath.Join(home, ".local", "share")
	default:
		return ""
	}
}
