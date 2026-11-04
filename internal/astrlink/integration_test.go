package astrlink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

// TestIntegrationRealModel runs only when K2F_ASTRLINK_DIR points at the
// real, verified model files. It is never part of the offline test run.
func TestIntegrationRealModel(t *testing.T) {
	if os.Getenv("K2F_ASTRLINK_DIR") == "" {
		t.Skip("K2F_ASTRLINK_DIR not set")
	}
	if testing.Short() {
		t.Skip("short mode")
	}
	st := Lookup()
	if !st.Available {
		t.Skipf("model unavailable: %s", st.Note)
	}
	m, err := loadModel(st.Dir)
	if err != nil {
		t.Fatalf("load model: %v", err)
	}
	text := "Alice's email is alice@example.com and her card is 4111 1111 1111 1111."
	spans, used, _, err := m.find(context.Background(), text, 0, nil)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if used == 0 {
		t.Fatal("no windows read")
	}
	if len(spans) == 0 {
		t.Fatal("no spans found in text with an email address and a card number")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Scan(context.Background(), []model.ExposureItem{
		{Path: path, Kind: "file", Exists: true},
	}, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.FilesScanned != 1 || len(res.Findings) == 0 {
		t.Fatalf("scan = %d files, %d findings", res.FilesScanned, len(res.Findings))
	}
	for _, f := range res.Findings {
		if f.Engine != "astrlink" || f.Value == "" || f.Masked == "" {
			t.Fatalf("bad finding: %+v", f)
		}
	}
}

// TestIntegrationCancelLatency cancels a multi-window find and checks that
// it returns promptly: the context is checked between layers, not only
// between windows, so a cancel does not wait for a whole window.
func TestIntegrationCancelLatency(t *testing.T) {
	if os.Getenv("K2F_ASTRLINK_DIR") == "" {
		t.Skip("K2F_ASTRLINK_DIR not set")
	}
	if testing.Short() {
		t.Skip("short mode")
	}
	st := Lookup()
	if !st.Available {
		t.Skipf("model unavailable: %s", st.Note)
	}
	m, err := loadModel(st.Dir)
	if err != nil {
		t.Fatalf("load model: %v", err)
	}
	// Several windows of tokens, so the cancel lands while inference runs.
	text := strings.Repeat("Alice's email is alice@example.com. ", 256)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, _, _, err := m.find(ctx, text, perFileWindows, nil)
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("find after cancel = %v, want context.Canceled", err)
		}
		// A layer, not a window. The bound is above one layer on a slow
		// single-core run and still below a whole window's inference.
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("cancel took %v, want under 2s", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("find did not return after cancel")
	}
}
