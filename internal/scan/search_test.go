package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/ioc"
)

func TestSanitizeSnippet(t *testing.T) {
	in := "abc\x00def\n\txyz" + strings.Repeat("字", 200)
	out := sanitizeSnippet(in)
	if strings.ContainsRune(out, 0) {
		t.Fatal("control nul survived")
	}
	if strings.ContainsAny(out, "\n\t") {
		t.Fatal("newline/tab survived")
	}
	n := 0
	for range out {
		n++
	}
	if n > maxSnippetRunes {
		t.Fatalf("len %d", n)
	}
}

func TestScanFileOverlap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "debug.log")
	pat := []byte("k2f_chan registered")
	buf := bytes.Repeat([]byte("x"), chunkSize-5)
	buf = append(buf, pat...)
	buf = append(buf, []byte(" tail")...)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	res := scanFile(path, []needle{{
		check: ioc.Check{ID: "log.k2f_chan"},
		pat:   pat,
	}}, true, int64(len(buf)+1024))
	if res.readErr != nil {
		t.Fatal(res.readErr)
	}
	if len(res.hits) != 1 {
		t.Fatalf("hits %d", len(res.hits))
	}
	if res.hits[0].offset != int64(chunkSize-5) {
		t.Fatalf("offset %d want %d", res.hits[0].offset, chunkSize-5)
	}
	if !strings.Contains(res.hits[0].snippet, "k2f_chan") {
		t.Fatalf("snippet %q", res.hits[0].snippet)
	}
	if res.sha256 == "" {
		t.Fatal("missing hash")
	}
}

func TestScanFileTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 64), 0o600); err != nil {
		t.Fatal(err)
	}
	res := scanFile(path, []needle{{pat: []byte("a")}}, false, 16)
	if !res.tooLarge {
		t.Fatal("expected tooLarge")
	}
	if len(res.hits) != 0 {
		t.Fatalf("hits %d", len(res.hits))
	}
}

func TestMatchFilename(t *testing.T) {
	if !matchFilename("dd65fa4d61079e7e_0", "dd65fa4d61079e7e_0") {
		t.Fatal("exact")
	}
	if !matchFilename("k2f_screen_*.jpg", "k2f_screen_1.jpg") {
		t.Fatal("glob")
	}
	prefix := "k2f-b" + "creds-" + "*"
	name := "k2f-b" + "creds-abc"
	if !matchFilename(prefix, name) {
		t.Fatal("dump prefix glob")
	}
	if matchFilename("dd65fa4d61079e7e_0", "other") {
		t.Fatal("false positive")
	}
}

func TestIsHex64(t *testing.T) {
	if !isHex64(strings.Repeat("ab", 32)) {
		t.Fatal("want true")
	}
	if isHex64(strings.Repeat("a", 63)) || isHex64(strings.Repeat("z", 64)) {
		t.Fatal("want false")
	}
}
