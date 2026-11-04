package clean

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/owogametools/k2f-purge/internal/model"
)

// Plan maps scan findings to a dry-run cleanup list. Items that fail
// the hard safety checks are dropped and recorded as warnings.
func Plan(scan *model.ScanResult) (*model.CleanPlan, error) {
	if scan == nil {
		return nil, fmt.Errorf("nil scan")
	}
	var targetPaths []string
	for _, t := range scan.Targets {
		if t.Path != "" {
			targetPaths = append(targetPaths, t.Path)
		}
	}
	roots := collectRoots(targetPaths)
	plan := &model.CleanPlan{ScanID: scan.ID}
	seen := map[string]struct{}{}

	for _, f := range scan.Findings {
		item, warn := itemFromFinding(f, roots)
		if warn != "" {
			plan.Warnings = append(plan.Warnings, warn)
		}
		if item == nil {
			continue
		}
		key := item.Kind + "\x00" + strings.ToLower(filepath.Clean(item.Path))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		plan.Items = append(plan.Items, *item)
		if item.RequiresRestart {
			plan.RequiresRestart = true
		}
	}
	return plan, nil
}

func itemFromFinding(f model.Finding, roots []string) (*model.CleanItem, string) {
	path := strings.TrimSpace(f.Path)
	if path == "" {
		return nil, ""
	}
	if isRegistryPath(path) || f.RuleID == "reg.clsid_hkcu" {
		if isForbiddenHive(path) {
			return nil, fmt.Sprintf("refused HKLM/non-HKCU registry path: %s", path)
		}
		key := path
		if !isRegistryPath(key) {
			key = `HKCU\Software\Classes\CLSID\` + k2fCLSID
		}
		if err := allowedRegistryKey(key); err != nil {
			return nil, fmt.Sprintf("refused registry key %s: %v", key, err)
		}
		item := makeItem(model.CleanRegistryCLSID, key, f, "HKCU CLSID persistence")
		item.ReasonZH = reasonZH(model.CleanRegistryCLSID)
		item.ReasonJA = reasonJA(model.CleanRegistryCLSID)
		return item, ""
	}

	kind := classify(f)
	if kind == "" {
		return nil, fmt.Sprintf("no cleanup mapping for rule %s (%s)", f.RuleID, path)
	}

	switch kind {
	case model.CleanChromeHelper:
		dir, err := chromeHelperDir(path)
		if err != nil {
			return nil, fmt.Sprintf("refused chrome helper %s: %v", path, err)
		}
		path = dir
	case model.CleanChromeLeftover:
		if !leftoverName(filepath.Base(path)) {
			return nil, fmt.Sprintf("refused leftover name %s", path)
		}
		if isHelperParent(path) {
			return nil, errHelperParent.Error()
		}
	case model.CleanLauncherCache:
		if r := findNamedAncestor(path, "tbs_cache"); r != "" {
			path = r
		}
	case model.CleanTinygetPayload:
		if r := findNamedAncestor(path, "tinyget"); r != "" {
			path = r
		}
	case model.CleanTempArtifacts:
		if !isTempArtifactName(filepath.Base(path)) {
			return nil, fmt.Sprintf("refused temp name %s", path)
		}
	}

	if isHelperParent(path) {
		return nil, fmt.Sprintf("%v: %s", errHelperParent, path)
	}
	if !underAny(path, roots) {
		return nil, fmt.Sprintf("%v: %s", errNotAllowlisted, path)
	}

	item := makeItem(kind, path, f, reasonFor(kind))
	item.ReasonZH = reasonZH(kind)
	item.ReasonJA = reasonJA(kind)
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			if _, err := resolveNoEscape(path, roots); err != nil {
				return nil, err.Error()
			}
		}
		if st.IsDir() {
			var size int64
			_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
				if err == nil && info != nil && !info.IsDir() {
					size += info.Size()
				}
				return nil
			})
			item.Size = size
		} else {
			item.Size = st.Size()
		}
	}
	return item, ""
}

func classify(f model.Finding) string {
	id := f.RuleID
	p := strings.ToLower(filepath.ToSlash(f.Path))
	base := strings.ToLower(filepath.Base(f.Path))

	if id == "chrome.helper_dll" || (strings.Contains(p, "platform_experience_helper.dll") && !strings.HasSuffix(p, ".old")) {
		return model.CleanChromeHelper
	}
	if id == "chrome.helper_leftover" || leftoverName(base) {
		return model.CleanChromeLeftover
	}
	if id == "temp.k2f_files" || isTempArtifactName(base) {
		if isWinePath(p) {
			return model.CleanWineArtifact
		}
		return model.CleanTempArtifacts
	}
	if isWinePath(p) {
		return model.CleanWineArtifact
	}
	if strings.Contains(p, "tinyget") || id == "log.payload_fetch" || id == "log.etag" || id == "log.lua_downloaded" {
		return model.CleanTinygetPayload
	}
	if strings.Contains(p, "tbs_cache") || id == "state.k2f_agent" || strings.HasPrefix(id, "cache.") {
		return model.CleanLauncherCache
	}
	if id == "log.k2f_chan" || id == "log.agent_started" {
		return model.CleanTinygetPayload
	}
	if id == "hash.known_bad" {
		if leftoverName(base) {
			return model.CleanChromeLeftover
		}
		if strings.Contains(p, "tinyget") {
			return model.CleanTinygetPayload
		}
	}
	return ""
}

func reasonFor(kind string) string {
	switch kind {
	case model.CleanRegistryCLSID:
		return "agent HKCU CLSID persistence"
	case model.CleanChromeHelper:
		return "PlatformExperienceHelper 64-hex payload"
	case model.CleanChromeLeftover:
		return "chrome helper leftover"
	case model.CleanLauncherCache:
		return "launcher tbs_cache (loader/agent state)"
	case model.CleanTinygetPayload:
		return "tinyget payload / log"
	case model.CleanTempArtifacts:
		return "k2f temp artifact"
	case model.CleanWineArtifact:
		return "wine/proton artifact"
	default:
		return kind
	}
}

func reasonZH(kind string) string {
	switch kind {
	case model.CleanRegistryCLSID:
		return "agent 的 HKCU CLSID 持久化"
	case model.CleanChromeHelper:
		return "PlatformExperienceHelper 64 碼 payload"
	case model.CleanChromeLeftover:
		return "Chrome 助手殘留"
	case model.CleanLauncherCache:
		return "啟動器 tbs_cache（loader／agent 狀態）"
	case model.CleanTinygetPayload:
		return "tinyget payload／日誌"
	case model.CleanTempArtifacts:
		return "k2f 暫存產物"
	case model.CleanWineArtifact:
		return "Wine／Proton 產物"
	default:
		return ""
	}
}

func reasonJA(kind string) string {
	switch kind {
	case model.CleanRegistryCLSID:
		return "agent の HKCU CLSID 永続化"
	case model.CleanChromeHelper:
		return "PlatformExperienceHelper 64 桁 payload"
	case model.CleanChromeLeftover:
		return "Chrome 補助の残留"
	case model.CleanLauncherCache:
		return "ランチャー tbs_cache（loader／agent 状態）"
	case model.CleanTinygetPayload:
		return "tinyget payload／ログ"
	case model.CleanTempArtifacts:
		return "k2f 一時成果物"
	case model.CleanWineArtifact:
		return "Wine／Proton 成果物"
	default:
		return ""
	}
}

func makeItem(kind, path string, f model.Finding, reason string) *model.CleanItem {
	sum := sha256.Sum256([]byte(kind + ":" + strings.ToLower(filepath.Clean(path))))
	return &model.CleanItem{
		ID:     hex.EncodeToString(sum[:8]),
		Kind:   kind,
		Path:   path,
		Reason: reason,
		RuleID: f.RuleID,
	}
}

func findNamedAncestor(path, name string) string {
	p := filepath.Clean(path)
	for {
		if strings.EqualFold(filepath.Base(p), name) {
			return p
		}
		next := filepath.Dir(p)
		if next == p {
			return ""
		}
		p = next
	}
}
