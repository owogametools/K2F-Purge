package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/owogametools/k2f-purge/internal/ioc"
)

var errTooLarge = errors.New("file exceeds MaxFileMB")

const (
	chunkSize       = 1 << 20
	maxSnippetRunes = 160
	snippetPad      = 80
)

type needle struct {
	check ioc.Check
	pat   []byte
}

type fileHit struct {
	check   ioc.Check
	offset  int64
	snippet string
	sha256  string
	size    int64
	mtime   time.Time
	path    string
}

type scanFileResult struct {
	hits     []fileHit
	sha256   string
	size     int64
	mtime    time.Time
	tooLarge bool
	readErr  error
	hashed   bool
}

func scanFile(path string, needles []needle, wantHash bool, maxBytes int64) scanFileResult {
	st, err := os.Lstat(path)
	if err != nil {
		return scanFileResult{readErr: err}
	}
	res := scanFileResult{size: st.Size(), mtime: st.ModTime()}
	if !st.Mode().IsRegular() {
		return res
	}
	if maxBytes > 0 && st.Size() > maxBytes {
		res.tooLarge = true
		return res
	}
	f, err := os.Open(path)
	if err != nil {
		res.readErr = err
		return res
	}
	defer f.Close()

	var h hash.Hash
	if wantHash {
		h = sha256.New()
	}
	overlap := 0
	for _, n := range needles {
		if l := len(n.pat) - 1; l > overlap {
			overlap = l
		}
	}
	buf := make([]byte, chunkSize+overlap)
	carry := 0
	var fileIndex int64
	seen := map[string]struct{}{}
	for {
		n, rerr := f.Read(buf[carry:])
		if n > 0 {
			data := buf[carry : carry+n]
			if wantHash {
				_, _ = h.Write(data)
			}
			window := buf[:carry+n]
			for _, nd := range needles {
				if len(nd.pat) == 0 {
					continue
				}
				idx := 0
				for {
					pos := bytes.Index(window[idx:], nd.pat)
					if pos < 0 {
						break
					}
					abs := fileIndex + int64(idx+pos)
					key := nd.check.ID
					if _, ok := seen[key]; ok {
						break
					}
					seen[key] = struct{}{}
					res.hits = append(res.hits, fileHit{
						check:   nd.check,
						offset:  abs,
						snippet: snippetAt(window, idx+pos, len(nd.pat)),
						path:    path,
						size:    st.Size(),
						mtime:   st.ModTime(),
					})
					idx += pos + len(nd.pat)
				}
			}
			if overlap > 0 && len(window) > overlap {
				copy(buf[:overlap], window[len(window)-overlap:])
				fileIndex += int64(len(window) - overlap)
				carry = overlap
			} else {
				fileIndex += int64(len(window))
				carry = 0
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			res.readErr = rerr
			break
		}
		if n == 0 {
			break
		}
	}
	if wantHash {
		res.sha256 = hex.EncodeToString(h.Sum(nil))
		res.hashed = true
		for i := range res.hits {
			res.hits[i].sha256 = res.sha256
		}
	}
	return res
}

func snippetAt(window []byte, idx, patLen int) string {
	start := idx - snippetPad
	if start < 0 {
		start = 0
	}
	end := idx + patLen + snippetPad
	if end > len(window) {
		end = len(window)
	}
	s := sanitizeSnippet(string(window[start:end]))
	if s == "" {
		return "[binary match]"
	}
	return s
}

func sanitizeSnippet(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if unicode.IsControl(r) {
			if r == '\n' || r == '\r' || r == '\t' {
				r = ' '
			} else {
				continue
			}
		}
		b.WriteRune(r)
		n++
		if n >= maxSnippetRunes {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func hashFile(path string, maxBytes int64) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if maxBytes > 0 && st.Size() > maxBytes {
		return "", errTooLarge
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
