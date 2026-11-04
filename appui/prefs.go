package appui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo/i18n"
)

// langPref is the language the app shows, as the user chose it. langPrefAuto
// follows the system locale; the others pin one shipped language.
type langPref int

const (
	langPrefAuto langPref = iota
	langPrefEN
	langPrefZH
	langPrefJA
)

// appPrefs is what settings.json holds. The file is additive: a build that
// does not know a field ignores it, and an older file loads with the zero
// value for a new one.
type appPrefs struct {
	Lang         string `json:"lang"`
	LauncherPath string `json:"launcherPath,omitempty"`
}

// prefsPathOverride lets tests keep the preference away from the real user
// config directory.
var prefsPathOverride string

func (p langPref) key() string {
	switch p {
	case langPrefEN:
		return "en"
	case langPrefZH:
		return "zh-Hant"
	case langPrefJA:
		return "ja"
	default:
		return "auto"
	}
}

func (p langPref) resolve() lang {
	switch p {
	case langPrefEN:
		return langEN
	case langPrefZH:
		return langZH
	case langPrefJA:
		return langJA
	default:
		return classifyTag(i18n.Locale())
	}
}

func parseLangPref(s string) langPref {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "en", "en-us", "en-gb":
		return langPrefEN
	case "zh", "zh-hant", "zh-tw", "zh-hk", "zh-mo":
		return langPrefZH
	case "ja", "ja-jp":
		return langPrefJA
	default:
		return langPrefAuto
	}
}

// langPrefLabel is the full option label, used in the popup.
func langPrefLabel(p langPref) string {
	switch p {
	case langPrefEN:
		return "EN"
	case langPrefZH:
		return "繁體中文"
	case langPrefJA:
		return "日本語"
	default:
		return tr("Auto (system)", "AUTO（跟隨系統）", "AUTO（システム）")
	}
}

// settingsPath is <UserConfigDir>/K2F PURGE/settings.json, the same root the
// quarantine uses.
func settingsPath() (string, error) {
	if prefsPathOverride != "" {
		return filepath.Join(prefsPathOverride, "settings.json"), nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "K2F PURGE", "settings.json"), nil
}

// readPrefs loads settings.json. A missing, unreadable, or invalid file
// yields the zero value, so old files and no file read the same.
func readPrefs() appPrefs {
	path, err := settingsPath()
	if err != nil {
		return appPrefs{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return appPrefs{}
	}
	var p appPrefs
	if err := json.Unmarshal(b, &p); err != nil {
		return appPrefs{}
	}
	return p
}

// writePrefs writes the whole file atomically: a temporary file in the same
// directory, then a rename.
func writePrefs(p appPrefs) error {
	path, err := settingsPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	f, err := os.CreateTemp(dir, "settings-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadLangPref reads the stored choice. A missing, unreadable, or invalid
// file means auto.
func loadLangPref() langPref {
	return parseLangPref(readPrefs().Lang)
}

// loadLauncherPath reads the saved custom Launcher directory. Empty means
// automatic discovery only.
func loadLauncherPath() string {
	return readPrefs().LauncherPath
}

// saveLangPref rewrites only the language field, so a saved launcher path
// survives a language change.
func saveLangPref(p langPref) error {
	prefs := readPrefs()
	prefs.Lang = p.key()
	return writePrefs(prefs)
}

// saveLauncherPath rewrites only the launcher path field, so a saved
// language choice survives. Empty clears the override.
func saveLauncherPath(path string) error {
	prefs := readPrefs()
	prefs.LauncherPath = path
	return writePrefs(prefs)
}
