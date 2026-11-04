package astrlink

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLookupMissingFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("K2F_ASTRLINK_DIR", dir)
	st := Lookup()
	if st.Available {
		t.Fatalf("Lookup = %+v, want unavailable", st)
	}
	if !strings.Contains(st.Note, "not found") {
		t.Fatalf("note = %q", st.Note)
	}
}

func TestLookupSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("K2F_ASTRLINK_DIR", dir)
	for _, f := range modelFiles {
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte("small"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st := Lookup()
	if st.Available {
		t.Fatalf("Lookup = %+v, want unavailable", st)
	}
	if !strings.Contains(st.Note, "size mismatch") {
		t.Fatalf("note = %q", st.Note)
	}
}

func TestLookupEnvOverrideOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("K2F_ASTRLINK_DIR", dir)
	st := Lookup()
	if st.Dir != dir {
		t.Fatalf("dir = %q, want %q", st.Dir, dir)
	}
}
