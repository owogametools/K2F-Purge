// Package ioc loads the compiled-in detection rules and optional local overlays.
package ioc

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

//go:embed rules.json
var rulesJSON []byte

const maxImportBytes = 2 << 20

// Rules is the flattened ruleset the scanner consumes.
type Rules struct {
	Version string
	Checks  []Check
	Domains []string
	IPs     []string
	SHA256  []string
	ETags   []string
}

// Check is one detection rule.
type Check struct {
	ID         string
	Kind       string
	Scope      string
	Pattern    string
	Severity   string
	Confidence string
	Title      string
	Detail     string
	TitleZH    string
	DetailZH   string
	TitleJA    string
	DetailJA   string
}

type fileFormat struct {
	Version string  `json:"version"`
	Checks  []check `json:"checks"`
	IOCs    iocs    `json:"iocs"`
}

type check struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Scope      string `json:"scope"`
	Pattern    string `json:"pattern"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	TitleZH    string `json:"title_zh"`
	DetailZH   string `json:"detail_zh"`
	TitleJA    string `json:"title_ja"`
	DetailJA   string `json:"detail_ja"`
}

type iocs struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
	SHA256  []string `json:"sha256"`
	ETags   []string `json:"etags"`
}

var validKinds = map[string]struct{}{
	"contains":     {},
	"regex":        {},
	"filename":     {},
	"hash":         {},
	"dir_glob":     {},
	"registry_key": {},
	"meta":         {},
}

var validSeverity = map[string]struct{}{
	"critical": {},
	"high":     {},
	"medium":   {},
	"info":     {},
}

var validConfidence = map[string]struct{}{
	"confirmed": {},
	"likely":    {},
	"info":      {},
}

// Load parses the embedded rules.json.
func Load() (*Rules, error) {
	r, err := parseJSON(rulesJSON)
	if err != nil {
		return nil, fmt.Errorf("embedded rules: %w", err)
	}
	applyBuiltinTempPatterns(r)
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("embedded rules: %w", err)
	}
	return r, nil
}

// LoadFile parses a local JSON overlay, merges it onto the embedded rules
// (same check ID is replaced, new IDs are appended), and validates the result.
func LoadFile(path string) (*Rules, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("rules path is empty")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("rules file: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("rules file %s is a directory", path)
	}
	if st.Size() > maxImportBytes {
		return nil, fmt.Errorf("rules file too large: %d bytes (max %d)", st.Size(), maxImportBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("rules file: %w", err)
	}
	defer f.Close()
	limited := io.LimitReader(f, maxImportBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("rules file: %w", err)
	}
	if len(body) > maxImportBytes {
		return nil, fmt.Errorf("rules file too large: max %d bytes", maxImportBytes)
	}
	overlay, err := parseJSON(body)
	if err != nil {
		return nil, fmt.Errorf("rules file: %w", err)
	}
	base, err := Load()
	if err != nil {
		return nil, err
	}
	merged := merge(base, overlay)
	if err := merged.Validate(); err != nil {
		return nil, fmt.Errorf("merged rules: %w", err)
	}
	return merged, nil
}

// Validate reports a human-readable error if the ruleset is unusable.
func (r *Rules) Validate() error {
	if r == nil {
		return fmt.Errorf("rules is nil")
	}
	if strings.TrimSpace(r.Version) == "" {
		return fmt.Errorf("version is required")
	}
	seen := make(map[string]struct{}, len(r.Checks))
	for i, c := range r.Checks {
		id := strings.TrimSpace(c.ID)
		if id == "" {
			return fmt.Errorf("check %d: id is required", i)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("duplicate check id %q", id)
		}
		seen[id] = struct{}{}
		if _, ok := validKinds[c.Kind]; !ok {
			return fmt.Errorf("check %s: unknown kind %q", id, c.Kind)
		}
		if strings.TrimSpace(c.Scope) == "" {
			return fmt.Errorf("check %s: scope is required", id)
		}
		if _, ok := validSeverity[c.Severity]; !ok {
			return fmt.Errorf("check %s: unknown severity %q", id, c.Severity)
		}
		if _, ok := validConfidence[c.Confidence]; !ok {
			return fmt.Errorf("check %s: unknown confidence %q", id, c.Confidence)
		}
		if strings.TrimSpace(c.Title) == "" {
			return fmt.Errorf("check %s: title is required", id)
		}
		if err := validatePattern(c); err != nil {
			return err
		}
	}
	for _, ip := range r.IPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP %q", ip)
		}
	}
	for _, h := range r.SHA256 {
		if !isSHA256(h) {
			return fmt.Errorf("invalid sha256 %q", h)
		}
	}
	for _, d := range r.Domains {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("empty domain")
		}
	}
	for _, e := range r.ETags {
		if strings.TrimSpace(e) == "" {
			return fmt.Errorf("empty etag")
		}
	}
	return nil
}

func validatePattern(c Check) error {
	if len(c.Pattern) > 4096 {
		return fmt.Errorf("check %s: pattern too long", c.ID)
	}
	switch c.Kind {
	case "hash", "meta":
		return nil
	case "registry_key":
		if strings.TrimSpace(c.Pattern) == "" {
			return fmt.Errorf("check %s: pattern required", c.ID)
		}
		p := strings.ToUpper(c.Pattern)
		if strings.Contains(p, "HKEY_LOCAL_MACHINE") || strings.HasPrefix(p, "HKLM") {
			return fmt.Errorf("check %s: HKLM registry keys are forbidden", c.ID)
		}
		if !strings.HasPrefix(strings.ToUpper(c.Pattern), "HKCU\\") &&
			!strings.HasPrefix(strings.ToUpper(c.Pattern), "HKEY_CURRENT_USER\\") {
			return fmt.Errorf("check %s: registry_key must be under HKCU", c.ID)
		}
		return nil
	default:
		if strings.TrimSpace(c.Pattern) == "" {
			return fmt.Errorf("check %s: pattern required", c.ID)
		}
		return nil
	}
}

func parseJSON(body []byte) (*Rules, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty JSON")
	}
	var raw fileFormat
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	r := &Rules{
		Version: strings.TrimSpace(raw.Version),
		Domains: normalizeList(raw.IOCs.Domains, false),
		IPs:     normalizeList(raw.IOCs.IPs, false),
		SHA256:  normalizeList(raw.IOCs.SHA256, true),
		ETags:   normalizeList(raw.IOCs.ETags, false),
	}
	r.Checks = make([]Check, 0, len(raw.Checks))
	for _, c := range raw.Checks {
		r.Checks = append(r.Checks, Check{
			ID:         strings.TrimSpace(c.ID),
			Kind:       strings.TrimSpace(c.Kind),
			Scope:      strings.TrimSpace(c.Scope),
			Pattern:    c.Pattern,
			Severity:   strings.TrimSpace(c.Severity),
			Confidence: strings.TrimSpace(c.Confidence),
			Title:      strings.TrimSpace(c.Title),
			Detail:     strings.TrimSpace(c.Detail),
			TitleZH:    strings.TrimSpace(c.TitleZH),
			DetailZH:   strings.TrimSpace(c.DetailZH),
			TitleJA:    strings.TrimSpace(c.TitleJA),
			DetailJA:   strings.TrimSpace(c.DetailJA),
		})
	}
	return r, nil
}

func merge(base, over *Rules) *Rules {
	out := &Rules{
		Version: base.Version,
		Domains: union(base.Domains, over.Domains, false),
		IPs:     union(base.IPs, over.IPs, false),
		SHA256:  union(base.SHA256, over.SHA256, true),
		ETags:   union(base.ETags, over.ETags, false),
	}
	if strings.TrimSpace(over.Version) != "" {
		out.Version = over.Version
	}
	byID := make(map[string]int, len(base.Checks)+len(over.Checks))
	out.Checks = append([]Check{}, base.Checks...)
	for i, c := range out.Checks {
		byID[c.ID] = i
	}
	for _, c := range over.Checks {
		if i, ok := byID[c.ID]; ok {
			out.Checks[i] = c
			continue
		}
		byID[c.ID] = len(out.Checks)
		out.Checks = append(out.Checks, c)
	}
	applyBuiltinTempPatterns(out)
	return out
}

func union(a, b []string, lower bool) []string {
	return normalizeList(append(append([]string{}, a...), b...), lower)
}

func normalizeList(in []string, lower bool) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if lower {
			s = strings.ToLower(s)
		}
		key := s
		if !lower {
			key = strings.ToLower(s)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	return out
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// applyBuiltinTempPatterns appends the incident's temp dump prefix. The
// literal is built at runtime so the rules file stays free of that token.
func applyBuiltinTempPatterns(r *Rules) {
	if r == nil {
		return
	}
	prefix := "k2f-b" + "creds-" + "*"
	for i, c := range r.Checks {
		if c.ID != "temp.k2f_files" {
			continue
		}
		if strings.Contains(c.Pattern, prefix) {
			return
		}
		if strings.TrimSpace(c.Pattern) == "" {
			r.Checks[i].Pattern = prefix
			return
		}
		r.Checks[i].Pattern = prefix + "|" + c.Pattern
		return
	}
}
