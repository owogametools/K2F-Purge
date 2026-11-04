package appui

import (
	"os"
	"sync"
	"testing"
)

// TestMain keeps every test away from the developer's real settings.json.
// Tests that need a fresh directory still use useTempPrefs.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "k2f-prefs-")
	if err != nil {
		os.Exit(m.Run())
	}
	prefsPathOverride = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func useTempPrefs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := prefsPathOverride
	prefsPathOverride = dir
	t.Cleanup(func() { prefsPathOverride = old })
	return dir
}

func resetLangState() {
	langOnce = sync.Once{}
	langPrefValue = langPrefAuto
	uiLang = langEN
}

func TestLangPrefRoundTrip(t *testing.T) {
	useTempPrefs(t)

	if got := loadLangPref(); got != langPrefAuto {
		t.Fatalf("missing file: got %v, want auto", got)
	}
	for _, want := range []langPref{langPrefEN, langPrefZH, langPrefJA, langPrefAuto} {
		if err := saveLangPref(want); err != nil {
			t.Fatalf("save %v: %v", want, err)
		}
		if got := loadLangPref(); got != want {
			t.Fatalf("round trip: got %v, want %v", got, want)
		}
	}
}

func TestLangPrefInvalidFileIsAuto(t *testing.T) {
	useTempPrefs(t)
	path, err := settingsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadLangPref(); got != langPrefAuto {
		t.Fatalf("invalid file: got %v, want auto", got)
	}
	if err := os.WriteFile(path, []byte(`{"lang":"zh-Hant"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadLangPref(); got != langPrefZH {
		t.Fatalf("stored zh-Hant: got %v, want ZH", got)
	}
}

func TestStoredLangWinsOverSystem(t *testing.T) {
	useTempPrefs(t)
	t.Setenv("K2F_UI_LANG", "")

	if err := saveLangPref(langPrefJA); err != nil {
		t.Fatal(err)
	}
	resetLangState()
	if got := pick3("en", "zh", "ja"); got != "ja" {
		t.Fatalf("stored JA: got %q, want ja", got)
	}
	if got := currentLangPref(); got != langPrefJA {
		t.Fatalf("current preference: got %v, want JA", got)
	}

	if err := saveLangPref(langPrefZH); err != nil {
		t.Fatal(err)
	}
	resetLangState()
	if got := pick3("en", "zh", "ja"); got != "zh" {
		t.Fatalf("stored ZH: got %q, want zh", got)
	}
}

func TestEnvOverridesStoredLang(t *testing.T) {
	useTempPrefs(t)
	t.Setenv("K2F_UI_LANG", "en")
	if err := saveLangPref(langPrefJA); err != nil {
		t.Fatal(err)
	}
	resetLangState()
	if got := pick3("en", "zh", "ja"); got != "en" {
		t.Fatalf("env override: got %q, want en", got)
	}
}

func TestSetLangPrefSwitchesImmediately(t *testing.T) {
	useTempPrefs(t)
	t.Setenv("K2F_UI_LANG", "")

	resetLangState()
	if err := setLangPref(langPrefJA); err != nil {
		t.Fatal(err)
	}
	if got := pick3("en", "zh", "ja"); got != "ja" {
		t.Fatalf("after switch: got %q, want ja", got)
	}
	if got := loadLangPref(); got != langPrefJA {
		t.Fatalf("stored after switch: got %v, want JA", got)
	}
}

func TestSetLangPrefStillStoresUnderEnv(t *testing.T) {
	useTempPrefs(t)
	t.Setenv("K2F_UI_LANG", "en")

	resetLangState()
	if err := setLangPref(langPrefZH); err != nil {
		t.Fatal(err)
	}
	if got := pick3("en", "zh", "ja"); got != "en" {
		t.Fatalf("env should keep rendering: got %q, want en", got)
	}
	if got := loadLangPref(); got != langPrefZH {
		t.Fatalf("stored under env: got %v, want ZH", got)
	}
}
