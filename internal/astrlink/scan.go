package astrlink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/owogametools/k2f-purge/internal/model"
)

// MinScore drops model spans below this probability. It matches the
// publisher's default and magpie's guard.MinScore; tests may tune it.
var MinScore = 0.8

const (
	perFileBytes   = 256 << 10
	perFileWindows = 8
	totalBytes     = 8 << 20
	maxWindows     = 512
	maxFindings    = 2000
	binaryPeekSize = 8 << 10
)

// excludedExt are archive, database, media and binary formats that carry
// no plain text worth tokenizing.
var excludedExt = map[string]bool{
	".db": true, ".sqlite": true, ".sqlite3": true, ".vscdb": true,
	".ldb": true, ".bin": true, ".exe": true, ".dll": true, ".zip": true,
	".gz": true, ".png": true, ".jpg": true, ".ico": true, ".woff": true,
	".woff2": true,
}

// Scan reads the present exposure catalog files with the local model.
// Only file, glob and env items that exist are read; directories,
// registry keys and symlinks are skipped. The model must have been found
// and verified by Lookup first. Cancelling ctx returns the partial result
// with ctx's error.
func Scan(ctx context.Context, items []model.ExposureItem, emit func(model.Progress)) (res *model.SecretResult, err error) {
	res = &model.SecretResult{
		StartedAt: time.Now(),
		Limitations: []string{
			"tokenizer normalizes per rune instead of per grapheme; multi-rune graphemes may differ",
		},
	}
	defer func() {
		if r := recover(); r != nil {
			res.FinishedAt = time.Now()
			err = fmt.Errorf("astrlink scan panic: %v", r)
		}
	}()
	if err := ctx.Err(); err != nil {
		res.FinishedAt = time.Now()
		return res, err
	}
	st := Lookup()
	if !st.Available {
		res.FinishedAt = time.Now()
		note := st.Note
		if note == "" {
			note = "astrlink model unavailable"
		}
		res.Limitations = append(res.Limitations, note)
		return res, errors.New(note)
	}
	m, err := loadModel(st.Dir)
	if err != nil {
		res.FinishedAt = time.Now()
		res.Limitations = append(res.Limitations, "model load failed: "+err.Error())
		return res, fmt.Errorf("astrlink model: %w", err)
	}
	return scanContent(ctx, m, items, emit, res)
}

type skipCounts struct {
	symlink, notRegular, excluded, binary, open int
	truncated                                   int
}

func scanContent(ctx context.Context, f finder, items []model.ExposureItem, emit func(model.Progress), res *model.SecretResult) (*model.SecretResult, error) {
	var cands []model.ExposureItem
	for _, it := range items {
		if !it.Exists || it.Path == "" {
			continue
		}
		switch it.Kind {
		case "file", "glob", "env":
			cands = append(cands, it)
		}
	}
	var counts skipCounts
	totalRead := int64(0)
	windowsLeft := maxWindows
	windowLimit := false
	findingLimit := false
	cappedFiles := 0
	seen := map[string]struct{}{}
	capped := false

	for i, it := range cands {
		if err := ctx.Err(); err != nil {
			res.FinishedAt = time.Now()
			return res, err
		}
		if len(res.Findings) >= maxFindings {
			findingLimit = true
			break
		}
		if windowsLeft <= 0 {
			windowLimit = true
			break
		}
		if totalRead >= totalBytes {
			capped = true
			break
		}
		path := it.Path
		info, err := os.Lstat(path)
		if err != nil {
			counts.open++
			res.FilesSkipped++
			report(emit, i+1, len(cands), path)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			counts.symlink++
			res.FilesSkipped++
			report(emit, i+1, len(cands), path)
			continue
		}
		if !info.Mode().IsRegular() {
			counts.notRegular++
			res.FilesSkipped++
			report(emit, i+1, len(cands), path)
			continue
		}
		if excludedExt[strings.ToLower(filepath.Ext(path))] {
			counts.excluded++
			res.FilesSkipped++
			report(emit, i+1, len(cands), path)
			continue
		}
		want := int64(perFileBytes)
		left := int64(totalBytes) - totalRead
		if left < want {
			want = left
		}
		data, err := readFile(path, want)
		if err != nil {
			counts.open++
			res.FilesSkipped++
			report(emit, i+1, len(cands), path)
			continue
		}
		if info.Size() > int64(len(data)) && want < perFileBytes {
			capped = true
		}
		totalRead += int64(len(data))
		res.BytesRead += int64(len(data))
		if info.Size() > int64(len(data)) {
			counts.truncated++
		}
		if len(data) == 0 {
			res.FilesScanned++
			report(emit, i+1, len(cands), path)
			continue
		}
		peek := data
		if len(peek) > binaryPeekSize {
			peek = peek[:binaryPeekSize]
		}
		if bytes.IndexByte(peek, 0) >= 0 {
			counts.binary++
			res.FilesSkipped++
			report(emit, i+1, len(cands), path)
			continue
		}
		res.FilesScanned++
		budget := min(perFileWindows, windowsLeft)
		reportSub(emit, i, len(cands), path, 0, budget)
		windowEmit := func(done, total int) {
			reportSub(emit, i, len(cands), path, done, total)
		}
		spans, used, limited, err := f.find(ctx, string(data), budget, windowEmit)
		windowsLeft -= used
		if limited {
			if budget == perFileWindows {
				// The per-file cap only shortens this file; the next one
				// still gets its own budget.
				cappedFiles++
			} else {
				// The global cap ran out inside this file.
				windowLimit = true
			}
		}
		if err != nil {
			res.FinishedAt = time.Now()
			return res, fmt.Errorf("%s: %w", path, err)
		}
		lineStarts := newlineStarts(data)
		for _, sp := range spans {
			if sp.Score < MinScore {
				continue
			}
			finding, ok := makeFinding(path, data, lineStarts, sp)
			if !ok {
				continue
			}
			key := finding.RuleID + "\x00" + finding.Fingerprint + "\x00" + finding.Path + "\x00" + strconv.Itoa(finding.Line)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			res.Findings = append(res.Findings, finding)
			if len(res.Findings) >= maxFindings {
				findingLimit = true
				break
			}
		}
		report(emit, i+1, len(cands), path)
		if findingLimit || windowsLeft <= 0 {
			if windowsLeft <= 0 {
				windowLimit = true
			}
			break
		}
	}

	if totalRead >= totalBytes {
		capped = true
	}
	res.Limitations = append(res.Limitations, skipNotes(counts)...)
	if capped {
		res.Limitations = append(res.Limitations, "total read cap of 8 MiB reached")
	}
	if cappedFiles > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf("%d files limited to %d windows", cappedFiles, perFileWindows))
	}
	if windowLimit {
		res.Limitations = append(res.Limitations, "window cap of 512 reached")
	}
	if findingLimit {
		res.Limitations = append(res.Limitations, "finding cap of 2000 reached")
	}
	res.FinishedAt = time.Now()
	return res, nil
}

func skipNotes(c skipCounts) []string {
	var out []string
	if n := c.symlink + c.notRegular; n > 0 {
		out = append(out, fmt.Sprintf("%d files skipped: symlink or not a regular file", n))
	}
	if c.excluded > 0 {
		out = append(out, fmt.Sprintf("%d files skipped: excluded extension", c.excluded))
	}
	if c.binary > 0 {
		out = append(out, fmt.Sprintf("%d binary files skipped", c.binary))
	}
	if c.open > 0 {
		out = append(out, fmt.Sprintf("%d files skipped: unreadable", c.open))
	}
	if c.truncated > 0 {
		out = append(out, fmt.Sprintf("%d files truncated at 256 KiB or the read cap", c.truncated))
	}
	return out
}

func report(emit func(model.Progress), done, total int, path string) {
	if emit != nil {
		emit(model.Progress{Done: done, Total: total, Current: path})
	}
}

// reportSub reports the windows read so far inside the file at done that
// index, so the interface can move while a large file is being read.
func reportSub(emit func(model.Progress), done, total int, path string, subDone, subTotal int) {
	if emit != nil {
		emit(model.Progress{Done: done, Total: total, Current: path, SubDone: subDone, SubTotal: subTotal})
	}
}

func readFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

func newlineStarts(b []byte) []int {
	starts := make([]int, 0, bytes.Count(b, []byte{'\n'})+1)
	starts = append(starts, 0)
	for i, c := range b {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func makeFinding(path string, data []byte, lineStarts []int, sp span) (model.SecretFinding, bool) {
	provider, kind, severity, ok := mapLabel(sp.Label)
	if !ok || sp.Start < 0 || sp.End > len(data) || sp.Start >= sp.End {
		return model.SecretFinding{}, false
	}
	lineIdx := sort.SearchInts(lineStarts, sp.Start+1) - 1
	if lineIdx < 0 {
		lineIdx = 0
	}
	value := string(data[sp.Start:sp.End])
	return model.SecretFinding{
		Engine:      "astrlink",
		RuleID:      "astrlink." + sp.Label,
		Provider:    provider,
		Kind:        kind,
		Severity:    severity,
		Confidence:  model.ConfidenceLikely,
		Path:        path,
		Line:        lineIdx + 1,
		Column:      utf8.RuneCount(data[lineStarts[lineIdx]:sp.Start]) + 1,
		Value:       value,
		Masked:      mask(value),
		Fingerprint: fingerprint(value),
		Score:       sp.Score,
	}, true
}

// mapLabel maps a model label to the finding it becomes. URL, IP address
// and private date are dropped as noise, as the design asks.
func mapLabel(label string) (provider, kind, severity string, ok bool) {
	switch label {
	case "common_secret":
		return "Generic secret", "secret", model.SeverityHigh, true
	case "private_person":
		return "PII", "person", model.SeverityMedium, true
	case "private_address":
		return "PII", "address", model.SeverityMedium, true
	case "phone":
		return "PII", "phone", model.SeverityMedium, true
	case "email":
		return "PII", "email", model.SeverityMedium, true
	case "account", "payment_card":
		return "PII", "account-number", model.SeverityHigh, true
	}
	return "", "", "", false
}

// mask keeps the first 6 and last 4 runes, or the first 2 and last 2 for
// short values.
func mask(v string) string {
	r := []rune(v)
	n := len(r)
	if n == 0 {
		return ""
	}
	if n <= 12 {
		a, b := min(2, n), min(2, n)
		return string(r[:a]) + "…" + string(r[n-b:])
	}
	return string(r[:6]) + "…" + string(r[n-4:])
}

// fingerprint is the first 12 hex characters of sha256(v).
func fingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:12]
}
