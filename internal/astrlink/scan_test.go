package astrlink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

type fakeFinder struct {
	spans   []span
	used    int
	limited bool
	err     error

	consume bool // report every offered window as used and capped
	emitSub bool // call emit for every window
	errFrom int  // when > 0, calls from this one on return err

	calls   int
	texts   []string
	budgets []int
}

func (f *fakeFinder) find(ctx context.Context, text string, maxWindows int, emit func(done, total int)) ([]span, int, bool, error) {
	f.calls++
	f.texts = append(f.texts, text)
	f.budgets = append(f.budgets, maxWindows)
	if f.emitSub && emit != nil {
		for i := 1; i <= maxWindows; i++ {
			emit(i, maxWindows)
		}
	}
	if f.err != nil && (f.errFrom == 0 || f.calls >= f.errFrom) {
		return nil, 0, false, f.err
	}
	if f.consume {
		return f.spans, maxWindows, true, nil
	}
	return f.spans, f.used, f.limited, nil
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanUnavailableModel(t *testing.T) {
	t.Setenv("K2F_ASTRLINK_DIR", t.TempDir())
	res, err := Scan(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("Scan succeeded without model files")
	}
	if res == nil || len(res.Limitations) == 0 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestScanMapsFindings(t *testing.T) {
	dir := t.TempDir()
	text := "first line\nalice@example.com\n"
	path := writeTestFile(t, dir, "notes.txt", text)
	emailAt := strings.Index(text, "alice")
	f := &fakeFinder{spans: []span{
		{0, 5, "common_secret", 0.91},
		{emailAt, emailAt + len("alice@example.com"), "email", 0.95},
		{0, 5, "common_secret", 0.91}, // duplicate
		{0, 3, "url", 0.99},           // dropped label
		{0, 3, "email", 0.5},          // below MinScore
	}}
	var progress []model.Progress
	res, err := scanContent(context.Background(), f, []model.ExposureItem{
		{Path: path, Kind: "file", Exists: true},
	}, func(p model.Progress) { progress = append(progress, p) }, &model.SecretResult{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(res.Findings), res.Findings)
	}
	if res.FilesScanned != 1 || res.BytesRead != int64(len(text)) {
		t.Fatalf("scanned = %d, bytes = %d", res.FilesScanned, res.BytesRead)
	}
	if len(progress) != 2 || progress[0].SubDone != 0 || progress[0].SubTotal != perFileWindows {
		t.Fatalf("progress = %+v", progress)
	}
	last := progress[len(progress)-1]
	if last.Done != 1 || last.Total != 1 || last.Current != path || last.SubTotal != 0 {
		t.Fatalf("progress = %+v", progress)
	}

	secret := res.Findings[0]
	if secret.Engine != "astrlink" || secret.RuleID != "astrlink.common_secret" {
		t.Fatalf("secret ids = %q %q", secret.Engine, secret.RuleID)
	}
	if secret.Provider != "Generic secret" || secret.Kind != "secret" || secret.Severity != model.SeverityHigh {
		t.Fatalf("secret mapping = %+v", secret)
	}
	if secret.Confidence != model.ConfidenceLikely || secret.Path != path {
		t.Fatalf("secret meta = %+v", secret)
	}
	if secret.Line != 1 || secret.Column != 1 || secret.Value != "first" {
		t.Fatalf("secret position = line %d col %d value %q", secret.Line, secret.Column, secret.Value)
	}
	if secret.Masked != "fi…st" {
		t.Fatalf("secret masked = %q", secret.Masked)
	}
	if len(secret.Fingerprint) != 12 {
		t.Fatalf("fingerprint = %q", secret.Fingerprint)
	}
	if secret.Score != 0.91 {
		t.Fatalf("score = %v", secret.Score)
	}

	email := res.Findings[1]
	if email.RuleID != "astrlink.email" || email.Kind != "email" || email.Severity != model.SeverityMedium {
		t.Fatalf("email mapping = %+v", email)
	}
	if email.Line != 2 || email.Column != 1 || email.Value != "alice@example.com" {
		t.Fatalf("email position = line %d col %d value %q", email.Line, email.Column, email.Value)
	}
	if email.Masked != "alice@….com" {
		t.Fatalf("email masked = %q", email.Masked)
	}
}

func TestScanMappingsDroppedLabels(t *testing.T) {
	dir := t.TempDir()
	text := "x"
	path := writeTestFile(t, dir, "x.txt", text)
	for _, label := range []string{"url", "ip_address", "private_date"} {
		f := &fakeFinder{spans: []span{{0, 1, label, 0.99}}}
		res, err := scanContent(context.Background(), f, []model.ExposureItem{{Path: path, Kind: "file", Exists: true}}, nil, &model.SecretResult{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("%s became a finding: %+v", label, res.Findings[0])
		}
	}
}

func TestScanSkipsNonText(t *testing.T) {
	dir := t.TempDir()
	good := writeTestFile(t, dir, "good.log", "hello")
	bin := writeTestFile(t, dir, "archive.bin", "hello")
	binary := writeTestFile(t, dir, "binary.log", "he\x00llo")
	dirItem := t.TempDir()
	f := &fakeFinder{}
	res, err := scanContent(context.Background(), f, []model.ExposureItem{
		{Path: good, Kind: "file", Exists: true},
		{Path: bin, Kind: "file", Exists: true},
		{Path: binary, Kind: "file", Exists: true},
		{Path: dirItem, Kind: "dir", Exists: true},
		{Path: filepath.Join(dir, "missing"), Kind: "file", Exists: false},
	}, nil, &model.SecretResult{})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || f.texts[0] != "hello" {
		t.Fatalf("finder calls = %d, texts = %v", f.calls, f.texts)
	}
	if res.FilesScanned != 1 || res.FilesSkipped != 2 {
		t.Fatalf("scanned = %d, skipped = %d", res.FilesScanned, res.FilesSkipped)
	}
	joined := strings.Join(res.Limitations, "\n")
	if !strings.Contains(joined, "excluded extension") || !strings.Contains(joined, "binary files skipped") {
		t.Fatalf("limitations = %v", res.Limitations)
	}
}

func TestScanSkipsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeTestFile(t, dir, "target.txt", "hello")
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	f := &fakeFinder{}
	res, err := scanContent(context.Background(), f, []model.ExposureItem{{Path: link, Kind: "file", Exists: true}}, nil, &model.SecretResult{})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 0 || res.FilesSkipped != 1 {
		t.Fatalf("calls = %d skipped = %d", f.calls, res.FilesSkipped)
	}
}

func TestScanPerFileCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", perFileBytes+1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeFinder{}
	res, err := scanContent(context.Background(), f, []model.ExposureItem{{Path: path, Kind: "file", Exists: true}}, nil, &model.SecretResult{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.texts) != 1 || len(f.texts[0]) != perFileBytes {
		t.Fatalf("finder saw %d bytes, want %d", len(f.texts[0]), perFileBytes)
	}
	if !strings.Contains(strings.Join(res.Limitations, "\n"), "truncated") {
		t.Fatalf("limitations = %v", res.Limitations)
	}
}

func TestScanFindingCap(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	var spans []span
	for i := 0; i < maxFindings+1; i++ {
		value := fmt.Sprintf("user%05d@example.com", i)
		start := sb.Len()
		sb.WriteString(value)
		sb.WriteString("\n")
		spans = append(spans, span{start, start + len(value), "email", 0.99})
	}
	path := writeTestFile(t, dir, "many.txt", sb.String())
	f := &fakeFinder{spans: spans}
	res, err := scanContent(context.Background(), f, []model.ExposureItem{{Path: path, Kind: "file", Exists: true}}, nil, &model.SecretResult{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != maxFindings {
		t.Fatalf("findings = %d, want %d", len(res.Findings), maxFindings)
	}
	if !strings.Contains(strings.Join(res.Limitations, "\n"), "finding cap") {
		t.Fatalf("limitations = %v", res.Limitations)
	}
}

func TestScanPerFileCapContinues(t *testing.T) {
	dir := t.TempDir()
	a := writeTestFile(t, dir, "a.txt", "hello")
	b := writeTestFile(t, dir, "b.txt", "world")
	f := &fakeFinder{consume: true}
	res, err := scanContent(context.Background(), f, []model.ExposureItem{
		{Path: a, Kind: "file", Exists: true},
		{Path: b, Kind: "file", Exists: true},
	}, nil, &model.SecretResult{})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 {
		t.Fatalf("finder calls = %d, want 2: the second file was starved", f.calls)
	}
	for i, budget := range f.budgets {
		if budget != perFileWindows {
			t.Fatalf("budget %d = %d, want %d", i, budget, perFileWindows)
		}
	}
	joined := strings.Join(res.Limitations, "\n")
	if !strings.Contains(joined, fmt.Sprintf("2 files limited to %d windows", perFileWindows)) {
		t.Fatalf("limitations = %v", res.Limitations)
	}
	if strings.Contains(joined, "window cap") {
		t.Fatalf("global cap reported for per-file caps: %v", res.Limitations)
	}
}

func TestScanGlobalWindowCapStops(t *testing.T) {
	dir := t.TempDir()
	n := maxWindows/perFileWindows + 1
	items := make([]model.ExposureItem, n)
	for i := range items {
		path := writeTestFile(t, dir, fmt.Sprintf("f%03d.txt", i), "x")
		items[i] = model.ExposureItem{Path: path, Kind: "file", Exists: true}
	}
	f := &fakeFinder{consume: true}
	res, err := scanContent(context.Background(), f, items, nil, &model.SecretResult{})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != maxWindows/perFileWindows {
		t.Fatalf("finder calls = %d, want %d", f.calls, maxWindows/perFileWindows)
	}
	if !strings.Contains(strings.Join(res.Limitations, "\n"), "window cap") {
		t.Fatalf("limitations = %v", res.Limitations)
	}
}

func TestScanWindowProgress(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "x.txt", "hello")
	f := &fakeFinder{emitSub: true, used: perFileWindows}
	var progress []model.Progress
	_, err := scanContent(context.Background(), f, []model.ExposureItem{{Path: path, Kind: "file", Exists: true}}, func(p model.Progress) {
		progress = append(progress, p)
	}, &model.SecretResult{})
	if err != nil {
		t.Fatal(err)
	}
	var sawStart, sawDone bool
	for _, p := range progress {
		if p.Current != path || p.SubTotal != perFileWindows {
			continue
		}
		if p.Done != 0 || p.Total != 1 {
			t.Fatalf("progress file counts = %d / %d", p.Done, p.Total)
		}
		if p.SubDone == 0 {
			sawStart = true
		}
		if p.SubDone == perFileWindows {
			sawDone = true
		}
	}
	if !sawStart || !sawDone {
		t.Fatalf("window progress = %+v, want SubDone 0 and %d", progress, perFileWindows)
	}
}

func TestScanCancelKeepsPartial(t *testing.T) {
	dir := t.TempDir()
	email := "alice@example.com"
	first := writeTestFile(t, dir, "a.txt", email)
	second := writeTestFile(t, dir, "b.txt", "hello")
	f := &fakeFinder{
		spans:   []span{{0, len(email), "email", 0.99}},
		err:     context.Canceled,
		errFrom: 2,
	}
	res, err := scanContent(context.Background(), f, []model.ExposureItem{
		{Path: first, Kind: "file", Exists: true},
		{Path: second, Kind: "file", Exists: true},
	}, nil, &model.SecretResult{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Value != email {
		t.Fatalf("partial findings = %+v", res.Findings)
	}
	if res.FinishedAt.IsZero() {
		t.Fatal("partial result has no finish time")
	}
}

func TestScanCancel(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "x.txt", "hello")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := scanContent(ctx, &fakeFinder{}, []model.ExposureItem{{Path: path, Kind: "file", Exists: true}}, nil, &model.SecretResult{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res == nil || res.FinishedAt.IsZero() {
		t.Fatalf("partial result = %+v", res)
	}
}

func TestWindowStarts(t *testing.T) {
	cases := []struct {
		n, max int
		want   []int
	}{
		{1, 0, []int{0}},
		{510, 0, []int{0}},
		{511, 0, []int{0, 382}},
		{1000, 0, []int{0, 382, 764}},
		{1000, 2, []int{0, 382}},
		{0, 0, []int{0}},
	}
	for _, c := range cases {
		got := windowStarts(c.n, c.max)
		if len(got) != len(c.want) {
			t.Fatalf("windowStarts(%d, %d) = %v, want %v", c.n, c.max, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("windowStarts(%d, %d) = %v, want %v", c.n, c.max, got, c.want)
			}
		}
	}
}

func TestMaskAndFingerprint(t *testing.T) {
	cases := map[string]string{
		"":                 "",
		"abcdefghijklmnop": "abcdef…mnop",
		"0123456789ab":     "01…ab",
		"abc":              "ab…bc",
	}
	for in, want := range cases {
		if got := mask(in); got != want {
			t.Fatalf("mask(%q) = %q, want %q", in, got, want)
		}
	}
	if got := fingerprint("abc"); got != "ba7816bf8f01" {
		t.Fatalf("fingerprint = %q", got)
	}
}
