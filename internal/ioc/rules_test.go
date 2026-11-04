package ioc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEmbedded(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.Version != "2026-11-04.1" {
		t.Fatalf("version %q", r.Version)
	}
	need := []string{
		"log.k2f_chan", "log.agent_started", "log.lua_downloaded",
		"log.adopted", "log.resuming", "log.payload_fetch",
		"state.k2f_agent", "cache.loader_url", "cache.loader_key",
		"cache.http_modified", "chrome.helper_dll", "reg.clsid_hkcu",
		"temp.k2f_files", "hash.known_bad", "log.etag",
	}
	got := map[string]Check{}
	for _, c := range r.Checks {
		got[c.ID] = c
	}
	for _, id := range need {
		if _, ok := got[id]; !ok {
			t.Errorf("missing check %s", id)
		}
	}
	if got["log.k2f_chan"].Confidence != "confirmed" || got["log.k2f_chan"].Severity != "critical" {
		t.Errorf("log.k2f_chan severity/confidence = %s/%s", got["log.k2f_chan"].Severity, got["log.k2f_chan"].Confidence)
	}
	if got["log.lua_downloaded"].Confidence != "likely" {
		t.Errorf("log.lua_downloaded confidence = %s", got["log.lua_downloaded"].Confidence)
	}
	if !strings.Contains(got["temp.k2f_files"].Pattern, "k2f_screen_*.jpg") {
		t.Errorf("temp pattern missing screenshot glob: %s", got["temp.k2f_files"].Pattern)
	}
	if !strings.Contains(got["temp.k2f_files"].Pattern, "k2f-b"+"creds-") {
		t.Errorf("temp pattern missing dump prefix: %s", got["temp.k2f_files"].Pattern)
	}
	if len(r.Domains) != 3 || len(r.IPs) != 2 || len(r.SHA256) != 3 || len(r.ETags) != 5 {
		t.Errorf("ioc counts domains=%d ips=%d sha=%d etags=%d", len(r.Domains), len(r.IPs), len(r.SHA256), len(r.ETags))
	}
}

func TestValidateTable(t *testing.T) {
	base := func() *Rules {
		return &Rules{
			Version: "t",
			Checks: []Check{{
				ID: "x", Kind: "contains", Scope: "launcher-log", Pattern: "k2f_chan registered",
				Severity: "critical", Confidence: "confirmed", Title: "t",
			}},
			IPs:     []string{"127.0.0.1"},
			SHA256:  []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Domains: []string{"example.test"},
			ETags:   []string{"abc"},
		}
	}
	tests := []struct {
		name    string
		mutate  func(*Rules)
		wantErr string
	}{
		{name: "ok", mutate: func(*Rules) {}, wantErr: ""},
		{name: "empty version", mutate: func(r *Rules) { r.Version = " " }, wantErr: "version"},
		{name: "empty id", mutate: func(r *Rules) { r.Checks[0].ID = "" }, wantErr: "id"},
		{name: "duplicate id", mutate: func(r *Rules) { r.Checks = append(r.Checks, r.Checks[0]) }, wantErr: "duplicate"},
		{name: "bad kind", mutate: func(r *Rules) { r.Checks[0].Kind = "explode" }, wantErr: "kind"},
		{name: "bad severity", mutate: func(r *Rules) { r.Checks[0].Severity = "fatal" }, wantErr: "severity"},
		{name: "bad confidence", mutate: func(r *Rules) { r.Checks[0].Confidence = "maybe" }, wantErr: "confidence"},
		{name: "missing pattern", mutate: func(r *Rules) { r.Checks[0].Pattern = "" }, wantErr: "pattern"},
		{name: "hash empty pattern ok", mutate: func(r *Rules) {
			r.Checks[0].Kind = "hash"
			r.Checks[0].Pattern = ""
			r.Checks[0].Scope = "any"
		}, wantErr: ""},
		{name: "hklm forbidden", mutate: func(r *Rules) {
			r.Checks[0].Kind = "registry_key"
			r.Checks[0].Scope = "registry"
			r.Checks[0].Pattern = `HKLM\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`
		}, wantErr: "HKLM"},
		{name: "bad ip", mutate: func(r *Rules) { r.IPs = []string{"999.1.1.1"} }, wantErr: "IP"},
		{name: "bad sha", mutate: func(r *Rules) { r.SHA256 = []string{"deadbeef"} }, wantErr: "sha256"},
		{name: "empty struct", mutate: func(r *Rules) { *r = Rules{} }, wantErr: "version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base()
			tt.mutate(r)
			err := r.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected err %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFileMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	body := `{
		"version": "overlay-1",
		"checks": [
			{
				"id": "log.k2f_chan",
				"kind": "contains",
				"scope": "launcher-log",
				"pattern": "k2f_chan registered",
				"severity": "critical",
				"confidence": "confirmed",
				"title": "overridden title",
				"detail": "from overlay"
			},
			{
				"id": "custom.extra",
				"kind": "contains",
				"scope": "launcher-log",
				"pattern": "custom-token",
				"severity": "info",
				"confidence": "info",
				"title": "Custom",
				"detail": "added"
			}
		],
		"iocs": {
			"domains": ["evil.example"],
			"ips": ["1.2.3.4"],
			"sha256": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
			"etags": ["deadbeef-1"]
		}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if r.Version != "overlay-1" {
		t.Fatalf("version %q", r.Version)
	}
	var chanTitle, extra bool
	for _, c := range r.Checks {
		if c.ID == "log.k2f_chan" {
			if c.Title != "overridden title" {
				t.Fatalf("title %q", c.Title)
			}
			chanTitle = true
		}
		if c.ID == "custom.extra" {
			extra = true
		}
	}
	if !chanTitle || !extra {
		t.Fatalf("merge missing override=%v extra=%v", chanTitle, extra)
	}
	if !contains(r.Domains, "evil.example") || !contains(r.Domains, "insightjs.com") {
		t.Fatalf("domains not unioned: %v", r.Domains)
	}
	if !contains(r.IPs, "1.2.3.4") {
		t.Fatalf("ips %v", r.IPs)
	}
}

func TestLoadFileTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, bytesRepeat('x', maxImportBytes+8), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadFileInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateNil(t *testing.T) {
	var r *Rules
	if err := r.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
