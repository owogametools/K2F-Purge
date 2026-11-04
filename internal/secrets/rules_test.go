package secrets

import "testing"

func TestRulesLoad(t *testing.T) {
	rules, version, err := Rules()
	if err != nil {
		t.Fatal(err)
	}
	if version == "" {
		t.Fatal("empty ruleset version")
	}
	if len(rules) < 20 {
		t.Fatalf("only %d rules", len(rules))
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.ID] {
			t.Fatalf("duplicate rule %s", r.ID)
		}
		seen[r.ID] = true
		if r.re == nil {
			t.Fatalf("rule %s not compiled", r.ID)
		}
		if r.Provider == "" || r.Kind == "" || r.Severity == "" {
			t.Fatalf("rule %s missing fields", r.ID)
		}
	}
}

func TestMask(t *testing.T) {
	long := fake("sk"+"-"+"proj"+"-", 24)
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abcd", "…"},
		{long, long[:6] + "…" + long[len(long)-4:]},
	}
	for _, c := range cases {
		if got := Mask(c.in); got != c.want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEntropyAndPlaceholder(t *testing.T) {
	if entropy("aaaaaaaaaaaaaaaa") != 0 {
		t.Fatal("entropy of repeated run should be 0")
	}
	random := fake("Zx9"+"_"+"Qw3"+"-", 16)
	if entropy(random) < 3 {
		t.Fatal("random value should be above 3")
	}
	if !placeholder("your" + "_api_key_here") {
		t.Fatal("placeholder not detected")
	}
	if placeholder(random) {
		t.Fatal("random value flagged as placeholder")
	}
}
