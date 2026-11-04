// Derived from yetone/magpie (MIT), Copyright (c) 2026 yetone.
// Source: internal/pii/guard/guard.go at
// 1a67ca614ed6a8180eaf6ea0442dd1272e43d603.

package astrlink

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
)

// labels are the model's BIO tags, by output index (its labels.json).
var labels = []string{"O",
	"B-email", "I-email", "B-phone", "I-phone", "B-account", "I-account",
	"B-payment_card", "I-payment_card", "B-ip_address", "I-ip_address",
	"B-url", "I-url", "B-common_secret", "I-common_secret",
	"B-private_address", "I-private_address", "B-private_date", "I-private_date",
	"B-private_person", "I-private_person"}

// window is how many tokens the model reads at once, besides <s> and
// </s>; a longer text is read in windows overlapping by overlap, each
// token labelled by the window it is furthest inside.
const (
	window  = maxPos - 2
	overlap = 128
	// floor is the probability under which a span is dropped before the
	// caller's MinScore threshold. It matches magpie's Floor.
	floor = 0.5
)

// guardModel is the model, loaded.
type guardModel struct {
	tok *tokenizer
	net *net
}

// span is what the model found: text[Start:End], a Label of its (email,
// phone, account, payment_card, ip_address, url, common_secret,
// private_address, private_date, private_person), and the least of its
// tokens' probabilities.
type span struct {
	Start, End int
	Label      string
	Score      float64
}

// cores is how many cores the model reads on at most: half of them, and
// never more than 4, as magpie's guard.Cores.
func cores() int { return max(1, min(4, runtime.GOMAXPROCS(0)/2)) }

// windowProcs is how many cores one window's matmuls may spread over. It
// leaves one core to the interface and divides the rest over the workers
// cores() sets, never more than 4: a 20-core machine runs 4 windows of 4.
func windowProcs() int {
	workers := cores()
	return max(1, min(4, (runtime.GOMAXPROCS(0)-1)/workers))
}

var (
	modelMu sync.Mutex
	models  = map[string]*guardModel{}
)

// loadModel reads the model in dir. A successfully loaded model is kept
// for the life of the process: the files are read-only release assets.
func loadModel(dir string) (*guardModel, error) {
	modelMu.Lock()
	defer modelMu.Unlock()
	if m := models[dir]; m != nil {
		return m, nil
	}
	tok, err := loadTokenizer(filepath.Join(dir, "tokenizer.json"))
	if err != nil {
		return nil, fmt.Errorf("tokenizer: %w", err)
	}
	if tok.vocab != vocabSize {
		return nil, fmt.Errorf("tokenizer: %d pieces, want %d", tok.vocab, vocabSize)
	}
	nt, err := loadNet(filepath.Join(dir, "model_int8.onnx"))
	if err != nil {
		return nil, fmt.Errorf("model: %w", err)
	}
	if nt.labels != len(labels) {
		return nil, fmt.Errorf("model: %d labels, not %d", nt.labels, len(labels))
	}
	if len(nt.posIDs) < maxPos {
		return nil, fmt.Errorf("model: position ids are %d, want %d", len(nt.posIDs), maxPos)
	}
	m := &guardModel{tok: tok, net: nt}
	models[dir] = m
	return m, nil
}

// finder is the inference half of Scan. Tests inject a fake to exercise
// the file, offset and finding logic without the 37 MB model.
type finder interface {
	// find labels text, reading at most maxWindows windows (0 = no cap).
	// emit, when not nil, is called as each window finishes with the count
	// done so far and the total. It returns the spans, how many windows
	// were read, and whether the cap left part of the text unread.
	find(ctx context.Context, text string, maxWindows int, emit func(done, total int)) (spans []span, used int, limited bool, err error)
}

// find runs the model over text and decodes its BIO tags into spans.
// Windows are read on at most cores() goroutines, windowProcs() cores
// each; the context is checked before every window and between every
// layer. A panic inside a worker is returned as an error, never left to
// end the process.
func (m *guardModel) find(ctx context.Context, text string, maxWindows int, emit func(done, total int)) (spans []span, used int, limited bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, false, err
	}
	toks := m.tok.encode(text)
	n := len(toks)
	if n == 0 {
		return nil, 0, false, nil
	}
	starts := windowStarts(n, maxWindows)
	limited = maxWindows > 0 && len(starts) < len(windowStarts(n, 0))
	if len(starts) == 0 {
		return nil, 0, limited, nil
	}
	ids := func(w int) []int {
		start := starts[w]
		end := min(start+window, n)
		out := make([]int, 0, end-start+2)
		out = append(out, 0)
		for _, t := range toks[start:end] {
			out = append(out, t.id)
		}
		return append(out, 2)
	}
	lgs := make([][]float32, len(starts))
	errs := make([]error, len(starts))
	workers := min(cores(), len(starts))
	procs := windowProcs()
	var next, done atomic.Int64
	var emitMu sync.Mutex
	var wg sync.WaitGroup
	var c carried
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.catch()
			for {
				w := int(next.Add(1)) - 1
				if w >= len(starts) {
					return
				}
				if ctx.Err() != nil {
					return
				}
				lg, err := m.net.logits(ctx, ids(w), procs)
				if err != nil {
					errs[w] = err
					return
				}
				lgs[w] = lg
				if emit != nil {
					emitMu.Lock()
					n := int(done.Add(1))
					emit(n, len(starts))
					emitMu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if p := c.load(); p != nil {
		return nil, 0, limited, fmt.Errorf("astrlink inference panic: %v", *p)
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, limited, err
	}
	for _, e := range errs {
		if e != nil {
			return nil, 0, limited, e
		}
	}
	for _, lg := range lgs {
		if lg != nil {
			used++
		}
	}
	lab := make([]int, n)
	prob := make([]float64, n)
	margin := make([]int, n)
	for i := range margin {
		margin[i] = -1
	}
	k := len(labels)
	for w, start := range starts {
		end := min(start+window, n)
		lg := lgs[w]
		if lg == nil {
			continue
		}
		for i := 0; i < end-start; i++ {
			j := start + i
			mg := min(i, end-start-1-i)
			if mg <= margin[j] {
				continue
			}
			row := lg[(i+1)*k : (i+2)*k]
			best, mx := 0, row[0]
			for col, v := range row {
				if v > mx {
					best, mx = col, v
				}
			}
			var sum float64
			for _, v := range row {
				sum += math.Exp(float64(v - mx))
			}
			margin[j], lab[j], prob[j] = mg, best, 1/sum
		}
	}
	return decode(toks, lab, prob), used, limited, nil
}

// windowStarts is the start token of each window over n tokens, with the
// tail window pulled back so it ends at n, as magpie's Find does. A
// positive maxWindows keeps only the first that many.
func windowStarts(n, maxWindows int) []int {
	var starts []int
	for start := 0; ; start = start + window - overlap {
		starts = append(starts, start)
		if start+window >= n {
			break
		}
	}
	if maxWindows > 0 && len(starts) > maxWindows {
		starts = starts[:maxWindows]
	}
	return starts
}

// decode reads the tokens' BIO tags (lab, by index into labels) into
// spans: a B tag, or an I tag of another kind than the span before it,
// starts one; an I tag of the same kind extends it; O ends it. A span's
// score is its least token's, and those under floor are dropped.
// Tokens of no text (a lone "▁") neither start nor end a span.
func decode(toks []token, lab []int, prob []float64) []span {
	var spans []span
	cur := -1
	for j, t := range toks {
		if t.start == t.end {
			continue
		}
		tag := labels[lab[j]]
		if tag == "O" {
			cur = -1
			continue
		}
		kind := tag[2:]
		if tag[0] == 'B' || cur < 0 || spans[cur].Label != kind {
			spans = append(spans, span{t.start, t.end, kind, prob[j]})
			cur = len(spans) - 1
			continue
		}
		spans[cur].End = t.end
		spans[cur].Score = min(spans[cur].Score, prob[j])
	}
	out := spans[:0]
	for _, s := range spans {
		if s.Score >= floor {
			out = append(out, s)
		}
	}
	return out
}
