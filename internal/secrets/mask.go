package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
)

// Mask keeps a value recognisable without showing all of it. The
// interface and the exported checklist show the full value; logs and
// action records use this.
func Mask(v string) string {
	r := []rune(v)
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 12:
		if len(r) <= 4 {
			return "…"
		}
		return string(r[:2]) + "…" + string(r[len(r)-2:])
	default:
		return string(r[:6]) + "…" + string(r[len(r)-4:])
	}
}

// Fingerprint is a stable, non-reversible identifier used for de-duping.
func Fingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:12]
}

// entropy is the Shannon entropy of the value in bits per byte. Random
// keys sit above 3; words and placeholders sit below.
func entropy(v string) float64 {
	if v == "" {
		return 0
	}
	counts := map[byte]int{}
	for i := 0; i < len(v); i++ {
		counts[v[i]]++
	}
	var e float64
	n := float64(len(v))
	for _, c := range counts {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

var placeholders = []string{
	"example", "sample", "placeholder", "your_", "your-", "changeme",
	"dummy", "xxxx", "0000", "${", "{{", "<", ">", "redacted", "fake",
	"test_key", "not_a_real", "insert_", "replace_", "todo", "none",
}

// placeholder says the value looks written by a human as a stand-in, not
// a live credential.
func placeholder(v string) bool {
	l := strings.ToLower(v)
	if l == "" {
		return true
	}
	for _, p := range placeholders {
		if strings.Contains(l, p) {
			return true
		}
	}
	// A run of one character, or an obvious sequence, is not a key.
	first := l[0]
	same := true
	for i := 1; i < len(l) && same; i++ {
		same = l[i] == first
	}
	if same {
		return true
	}
	for _, seq := range []string{"123456", "abcdef", "qwerty", "000000"} {
		if strings.Contains(l, seq) {
			return true
		}
	}
	return false
}

func validValue(v string, r Rule) bool {
	if v == "" || placeholder(v) {
		return false
	}
	if r.Entropy > 0 && entropy(v) < r.Entropy {
		return false
	}
	return true
}
