// Package secrets finds exposed API keys and other credentials in the
// files the exposure catalogue marks as present. It reads file contents
// only when the user explicitly asks for a content scan.
package secrets

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed rules.json
var rulesJSON []byte

// Rule is one compiled secret pattern.
type Rule struct {
	ID         string  `json:"id"`
	Provider   string  `json:"provider"`
	Kind       string  `json:"kind"`
	Severity   string  `json:"severity"`
	Confidence string  `json:"confidence"`
	Pattern    string  `json:"regex"`
	Group      int     `json:"group"`
	Entropy    float64 `json:"entropy"`
	Action     string  `json:"action"`
	ActionZH   string  `json:"action_zh"`
	ActionJA   string  `json:"action_ja"`

	re *regexp.Regexp
}

type ruleFile struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

var (
	rulesetVersion string
	rules          []Rule
	rulesErr       error
)

func init() {
	rules, rulesetVersion, rulesErr = loadRules(rulesJSON)
}

func loadRules(b []byte) ([]Rule, string, error) {
	var f ruleFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, "", fmt.Errorf("secrets rules: %w", err)
	}
	if len(f.Rules) == 0 {
		return nil, "", fmt.Errorf("secrets rules: empty")
	}
	seen := map[string]struct{}{}
	out := make([]Rule, 0, len(f.Rules))
	for _, r := range f.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return nil, "", fmt.Errorf("secrets rules: empty id")
		}
		if _, ok := seen[r.ID]; ok {
			return nil, "", fmt.Errorf("secrets rules: duplicate id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		if len(r.Pattern) == 0 || len(r.Pattern) > 400 {
			return nil, "", fmt.Errorf("secrets rule %s: pattern length %d", r.ID, len(r.Pattern))
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, "", fmt.Errorf("secrets rule %s: %w", r.ID, err)
		}
		if r.Group < 0 || r.Group > re.NumSubexp() {
			return nil, "", fmt.Errorf("secrets rule %s: group %d of %d", r.ID, r.Group, re.NumSubexp())
		}
		if !validSeverity(r.Severity) {
			return nil, "", fmt.Errorf("secrets rule %s: severity %q", r.ID, r.Severity)
		}
		if !validConfidence(r.Confidence) {
			return nil, "", fmt.Errorf("secrets rule %s: confidence %q", r.ID, r.Confidence)
		}
		r.re = re
		out = append(out, r)
	}
	return out, f.Version, nil
}

func validSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "info":
		return true
	}
	return false
}

func validConfidence(s string) bool {
	switch s {
	case "confirmed", "likely", "info":
		return true
	}
	return false
}

// Rules returns the compiled rules. It is used by tests and by the export
// header that names the ruleset version.
func Rules() ([]Rule, string, error) { return rules, rulesetVersion, rulesErr }
