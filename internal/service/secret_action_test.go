package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestSecretScanActionHidesValue(t *testing.T) {
	value := "sk" + "-" + "proj" + "-" + "Ab3x" + "Y9Ab" + "3xY9" + "Ab3x" + "Y9Ab"
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("key = "+value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Service{exposure: &model.ExposureResult{Items: []model.ExposureItem{{Kind: "file", Path: path, Exists: true}}}}
	res, err := s.SecretScan(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Value != value {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(s.actions) != 1 {
		t.Fatalf("actions = %+v", s.actions)
	}
	if strings.Contains(s.actions[0].Detail, value) {
		t.Fatal("action record contains the full secret")
	}
}
