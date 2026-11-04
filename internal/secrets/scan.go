package secrets

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/owogametools/k2f-purge/internal/model"
)

const (
	maxFileBytes  = 8 << 20
	maxLineBytes  = 1 << 20
	maxFiles      = 4096
	maxFindings   = 2000
	maxTotalBytes = 64 << 20
)

var skipExt = map[string]struct{}{
	".db": {}, ".sqlite": {}, ".sqlite3": {}, ".vscdb": {}, ".ldb": {},
	".bin": {}, ".exe": {}, ".dll": {}, ".zip": {}, ".gz": {}, ".png": {},
	".jpg": {}, ".jpeg": {}, ".ico": {}, ".woff": {}, ".woff2": {},
}

// Scan reads the files the exposure catalogue found and returns every
// credential-like value it recognises. It never walks directories and
// never follows a symlink.
func Scan(ctx context.Context, items []model.ExposureItem, emit func(model.Progress)) (*model.SecretResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rulesErr != nil {
		return nil, rulesErr
	}
	started := time.Now().UTC()
	res := &model.SecretResult{StartedAt: started}

	paths := candidatePaths(items)
	if len(paths) == 0 {
		res.FinishedAt = time.Now().UTC()
		res.Limitations = []string{"no present files in the exposure result"}
		return res, nil
	}

	seen := map[string]struct{}{}
	truncatedLine := false
	unreadable := 0
	overSize := 0
	binary := 0
	stopped := ""
	total := len(paths)

	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			res.Limitations = append(res.Limitations, "scan cancelled before completion")
			res.FinishedAt = time.Now().UTC()
			return res, err
		}
		if res.FilesScanned >= maxFiles {
			stopped = fmt.Sprintf("file cap reached (%d)", maxFiles)
			break
		}
		if res.BytesRead >= maxTotalBytes {
			stopped = fmt.Sprintf("total read cap reached (%d MiB)", maxTotalBytes>>20)
			break
		}
		if len(res.Findings) >= maxFindings {
			stopped = fmt.Sprintf("finding cap reached (%d)", maxFindings)
			break
		}

		if _, skip := skipExt[strings.ToLower(filepath.Ext(path))]; skip {
			res.FilesSkipped++
			continue
		}
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			res.FilesSkipped++
			continue
		}
		if st.Size() > maxFileBytes {
			res.FilesSkipped++
			overSize++
			continue
		}

		f, err := os.Open(path)
		if err != nil {
			res.FilesSkipped++
			unreadable++
			continue
		}

		head := make([]byte, 8192)
		n, _ := io.ReadFull(f, head)
		if isBinary(head[:n]) {
			_ = f.Close()
			res.FilesSkipped++
			binary++
			continue
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			res.FilesSkipped++
			unreadable++
			continue
		}

		res.FilesScanned++
		read, truncated, err := scanLines(ctx, f, path, res, seen)
		_ = f.Close()
		res.BytesRead += read
		truncatedLine = truncatedLine || truncated
		if err != nil {
			if ctx.Err() != nil {
				res.Limitations = append(res.Limitations, "scan cancelled before completion")
				res.FinishedAt = time.Now().UTC()
				return res, ctx.Err()
			}
			unreadable++
		}
		if emit != nil {
			emit(model.Progress{Done: i + 1, Total: total, Current: path})
		}
	}

	sortFindings(res.Findings)

	res.FinishedAt = time.Now().UTC()
	res.Limitations = append(res.Limitations,
		"content scan is opt-in and only reads files already listed as present by the path check",
		"values are shown in full in the interface and in the export; logs use a mask",
		"ruleset "+rulesetVersion,
	)
	if binary > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf("skipped %d binary files", binary))
	}
	if overSize > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf("skipped %d files over %d MiB", overSize, maxFileBytes>>20))
	}
	if unreadable > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf("could not read %d files", unreadable))
	}
	if truncatedLine {
		res.Limitations = append(res.Limitations, fmt.Sprintf("lines over %d KiB were truncated before matching", maxLineBytes>>10))
	}
	if stopped != "" {
		res.Limitations = append(res.Limitations, stopped)
	}

	sort.Strings(res.Limitations)
	return res, nil
}

func candidatePaths(items []model.ExposureItem) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, it := range items {
		if !it.Exists || it.Path == "" {
			continue
		}
		switch it.Kind {
		case "file", "glob", "env":
		default:
			continue
		}
		key := filepath.Clean(it.Path)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, it.Path)
	}
	sort.Strings(out)
	return out
}

func isBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// scanLines reads f line by line and appends findings to res. It returns
// the bytes read and whether any line was truncated.
func scanLines(ctx context.Context, f *os.File, path string, res *model.SecretResult, seen map[string]struct{}) (int64, bool, error) {
	br := bufio.NewReaderSize(f, 64<<10)
	var read int64
	lineNo := 0
	truncated := false
	for {
		if lineNo%256 == 0 {
			if err := ctx.Err(); err != nil {
				return read, truncated, err
			}
		}
		raw, err := br.ReadString('\n')
		if len(raw) > 0 {
			read += int64(len(raw))
			lineNo++
			line := strings.TrimRight(raw, "\r\n")
			if len(line) > maxLineBytes {
				line = line[:maxLineBytes]
				truncated = true
			}
			for i := range rules {
				r := &rules[i]
				matches := r.re.FindAllStringSubmatchIndex(line, 8)
				for _, m := range matches {
					si, ei := m[0], m[1]
					if r.Group > 0 && len(m) >= 2*(r.Group+1) {
						si, ei = m[2*r.Group], m[2*r.Group+1]
					}
					if si < 0 || ei <= si || ei > len(line) {
						continue
					}
					value := line[si:ei]
					// The shortest value any rule may capture is a
					// connection-string password (6); the generic
					// assignment rule already demands 16.
					if len(value) < 6 || !validValue(value, *r) {
						continue
					}
					fp := Fingerprint(value)
					// The first rule wins: the specific provider
					// patterns come before the generic assignment rule,
					// so one key is reported once.
					key := fp + "\x00" + path + "\x00" + fmt.Sprint(lineNo)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					res.Findings = append(res.Findings, model.SecretFinding{
						Engine:      "rule",
						RuleID:      r.ID,
						Provider:    r.Provider,
						Kind:        r.Kind,
						Severity:    r.Severity,
						Confidence:  r.Confidence,
						Path:        path,
						Line:        lineNo,
						Column:      utf8.RuneCountInString(line[:si]) + 1,
						Value:       value,
						Masked:      Mask(value),
						Fingerprint: fp,
						Action:      r.Action,
						ActionZH:    r.ActionZH,
						ActionJA:    r.ActionJA,
					})
					if len(res.Findings) >= maxFindings {
						return read, truncated, nil
					}
				}
			}
		}
		if err == io.EOF {
			return read, truncated, nil
		}
		if err != nil {
			return read, truncated, err
		}
	}
}

func sortFindings(f []model.SecretFinding) {
	rank := func(s string) int {
		switch s {
		case "critical":
			return 0
		case "high":
			return 1
		case "medium":
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(f, func(i, j int) bool {
		if rank(f[i].Severity) != rank(f[j].Severity) {
			return rank(f[i].Severity) < rank(f[j].Severity)
		}
		if f[i].Provider != f[j].Provider {
			return f[i].Provider < f[j].Provider
		}
		if f[i].Path != f[j].Path {
			return f[i].Path < f[j].Path
		}
		return f[i].Line < f[j].Line
	})
}
