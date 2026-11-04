package appui

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/egoist/mygo/i18n"
)

type lang int

const (
	langEN lang = iota
	langZH
	langJA
)

var (
	langOnce      sync.Once
	uiLang        lang
	langPrefValue langPref
)

// tr says the text in the language the app shows: Japanese, Traditional
// Chinese, or English. The user's stored choice wins; auto asks the system.
// An empty translation falls back to English.
//
// K2F_UI_LANG, when set, is read first and wins over the stored choice.
// LANG/LC_ALL do not change i18n.Locale on Windows; this env hook is how
// tests render a chosen language. "ja" and "ja-JP" force Japanese;
// "zh-Hant" and "zh-TW" force Traditional Chinese; "en" forces English.
// Any other value is normalized and classified the same way as the
// system locale.
func tr(en, zh, ja string) string {
	return pick3(en, zh, ja)
}

func trf(en, zh, ja string, args ...any) string {
	s := tr(en, zh, ja)
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// pick3 returns the first non-empty value for the active language.
// English is used if both translations are empty.
func pick3(en, zh, ja string) string {
	langOnce.Do(resolveLang)
	switch uiLang {
	case langJA:
		if strings.TrimSpace(ja) != "" {
			return ja
		}
	case langZH:
		if strings.TrimSpace(zh) != "" {
			return zh
		}
	}
	return en
}

// resolveLang reads the stored choice once. K2F_UI_LANG still wins so tests
// and previews can pin a language; otherwise the stored choice decides, and
// auto follows the system locale.
func resolveLang() {
	langPrefValue = loadLangPref()
	if tag := strings.TrimSpace(os.Getenv("K2F_UI_LANG")); tag != "" {
		uiLang = classifyTag(tag)
		return
	}
	uiLang = langPrefValue.resolve()
}

// currentLangPref is the choice the menu shows.
func currentLangPref() langPref {
	langOnce.Do(resolveLang)
	return langPrefValue
}

// setLangPref applies p for this session and stores it. A failing save is
// reported to the caller; the session still switches.
func setLangPref(p langPref) error {
	langOnce.Do(resolveLang)
	langPrefValue = p
	if strings.TrimSpace(os.Getenv("K2F_UI_LANG")) == "" {
		uiLang = p.resolve()
	}
	return saveLangPref(p)
}

func classifyTag(tag string) lang {
	tag = i18n.Normalize(tag)
	base := i18n.Base(tag)
	if base == "ja" {
		return langJA
	}
	if base != "zh" {
		return langEN
	}
	lower := strings.ToLower(tag)
	// Simplified Chinese is not shipped; keep English.
	if strings.Contains(lower, "hans") ||
		lower == "zh-cn" || strings.HasPrefix(lower, "zh-cn-") ||
		lower == "zh-sg" || strings.HasPrefix(lower, "zh-sg-") {
		return langEN
	}
	return langZH
}

func cjkUI() bool {
	langOnce.Do(resolveLang)
	return uiLang != langEN
}

func pageLabel(p Page) string {
	switch p {
	case PageScan:
		return tr("Scan", "掃描", "走査")
	case PageVerdict:
		return tr("Verdict", "判定", "判定")
	case PageBlock:
		return tr("Block", "封鎖", "遮断")
	case PageClean:
		return tr("Clean", "清理", "清掃")
	case PageExposure:
		return tr("Exposure", "曝險", "露出")
	case PageReport:
		return tr("Report", "報告", "報告")
	default:
		return p.Name()
	}
}
