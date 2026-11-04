package exposure

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestCatalogCounts(t *testing.T) {
	items := Catalog()
	if len(items) < 250 {
		t.Fatalf("catalog len %d, want >= 250", len(items))
	}
	if n := len(catalogByGroup(groupPath)); n != 250 {
		t.Fatalf("path items %d, want 250", n)
	}
	if n := len(catalogByGroup(groupEnv)); n != 16 {
		t.Fatalf("env items %d, want 16", n)
	}
	if n := len(catalogByGroup(groupBrowser)); n != 17 {
		t.Fatalf("browser items %d, want 17", n)
	}
	if n := len(catalogByGroup(groupRegistry)); n != 7 {
		t.Fatalf("registry items %d, want 7", n)
	}

	seen := map[string]string{}
	for _, it := range items {
		if it.ID == "" {
			t.Fatalf("empty id for path %s", it.Path)
		}
		if it.Category == "" {
			t.Fatalf("empty category for %s", it.ID)
		}
		if it.Kind == "" || it.Path == "" || it.Label == "" || it.Action == "" {
			t.Fatalf("incomplete item %s", it.ID)
		}
		if prev, ok := seen[it.ID]; ok {
			t.Fatalf("duplicate id %s (%s and %s)", it.ID, prev, it.Path)
		}
		seen[it.ID] = it.Path
		if strings.Contains(it.ID, "_") || strings.ToLower(it.ID) != it.ID {
			t.Errorf("id not kebab-case: %s", it.ID)
		}
	}
}

func TestCatalogGroupsCoverRequiredCategories(t *testing.T) {
	need := map[string]bool{}
	for _, n := range categoryOrder {
		need[n] = false
	}
	for _, it := range Catalog() {
		need[it.Category] = true
	}
	for _, n := range categoryOrder {
		if !need[n] {
			t.Errorf("category %s has no items", n)
		}
	}
}

func TestCatalogKinds(t *testing.T) {
	allowed := map[string]struct{}{
		"file": {}, "dir": {}, "glob": {}, "registry": {}, "env": {},
	}
	for _, it := range Catalog() {
		if _, ok := allowed[it.Kind]; !ok {
			t.Errorf("%s kind %q", it.ID, it.Kind)
		}
	}
	var foundNikke, foundCLSID bool
	for _, it := range Catalog() {
		if strings.Contains(it.Path, "nikke_launcher") && !strings.Contains(it.Path, "hmt") {
			foundNikke = true
		}
		if strings.Contains(strings.ToLower(it.Path), "e77cc89b") {
			foundCLSID = true
		}
	}
	if !foundNikke || !foundCLSID {
		t.Fatalf("missing nikke or CLSID catalog entries")
	}
}

func mustGOOS(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "" {
		t.Fatal("no GOOS")
	}
	return runtime.GOOS
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findItem(items []model.ExposureItem, id string) (model.ExposureItem, bool) {
	for _, it := range items {
		if it.ID == id || strings.HasPrefix(it.ID, id+"#") {
			return it, true
		}
	}
	return model.ExposureItem{}, false
}
