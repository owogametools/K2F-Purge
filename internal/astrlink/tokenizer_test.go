package astrlink

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTokenizer builds a small tokenizer.json. The charsmap is an empty
// trie (length 0 followed by no units), so normalization is identity.
func writeTokenizer(t *testing.T, vocab [][2]any) string {
	t.Helper()
	doc := map[string]any{
		"added_tokens": []any{
			map[string]any{"id": 0, "content": "<s>", "special": true},
			map[string]any{"id": 2, "content": "</s>", "special": true},
		},
		"normalizer": map[string]any{
			"type":                 "Precompiled",
			"precompiled_charsmap": base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0}),
		},
		"model": map[string]any{
			"type":   "Unigram",
			"unk_id": 0,
			"vocab":  vocab,
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tokenizer.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTokenizerUnigramWholePieces(t *testing.T) {
	path := writeTokenizer(t, [][2]any{
		{"<unk>", 0.0},
		{"▁hello", -1.0},
		{"▁world", -1.0},
	})
	tok, err := loadTokenizer(path)
	if err != nil {
		t.Fatal(err)
	}
	got := tok.encode("hello world")
	if len(got) != 2 {
		t.Fatalf("tokens = %v, want 2", got)
	}
	if got[0].id != 1 || got[0].start != 0 || got[0].end != 5 {
		t.Fatalf("token 0 = %+v", got[0])
	}
	if got[1].id != 2 || got[1].start != 6 || got[1].end != 11 {
		t.Fatalf("token 1 = %+v", got[1])
	}
}

func TestTokenizerUnigramSplitOffsets(t *testing.T) {
	path := writeTokenizer(t, [][2]any{
		{"<unk>", 0.0},
		{"▁he", -1.0},
		{"llo", -1.0},
		{"▁world", -1.0},
	})
	tok, err := loadTokenizer(path)
	if err != nil {
		t.Fatal(err)
	}
	got := tok.encode("hello world")
	if len(got) != 3 {
		t.Fatalf("tokens = %v, want 3", got)
	}
	want := []token{{1, 0, 2}, {2, 2, 5}, {3, 6, 11}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestTokenizerOffsetsWithMultibyte(t *testing.T) {
	path := writeTokenizer(t, [][2]any{
		{"<unk>", 0.0},
		{"▁你好", -1.0},
	})
	tok, err := loadTokenizer(path)
	if err != nil {
		t.Fatal(err)
	}
	got := tok.encode("你好")
	if len(got) != 1 {
		t.Fatalf("tokens = %v", got)
	}
	// "你" and "好" are three bytes each.
	if got[0].id != 1 || got[0].start != 0 || got[0].end != 6 {
		t.Fatalf("token = %+v", got[0])
	}
}

func TestTokenizerRejectsBadModel(t *testing.T) {
	path := writeTokenizer(t, [][2]any{{"<unk>", 0.0}})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc["model"].(map[string]any)["type"] = "BPE"
	b, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTokenizer(path); err == nil {
		t.Fatal("loadTokenizer accepted a BPE model")
	}
}
