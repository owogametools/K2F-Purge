package astrlink

import (
	"math"
	"testing"
)

func TestQuantDynamic(t *testing.T) {
	q, scale, zp := quant([]float32{-1, 0, 1})
	if scale != float32(2)/255 {
		t.Fatalf("scale = %v", scale)
	}
	// float32's scale makes -1/scale just under 127.5, so round-to-even
	// gives 127 (upstream computes the same).
	if zp != 127 {
		t.Fatalf("zp = %d, want 127", zp)
	}
	want := []uint8{0, 127, 254}
	for i := range want {
		if q[i] != want[i] {
			t.Fatalf("q = %v, want %v", q, want)
		}
	}
}

func TestQuantConstant(t *testing.T) {
	q, scale, zp := quant([]float32{2, 2, 2})
	if scale != float32(2)/255 || zp != 0 {
		t.Fatalf("scale, zp = %v, %d", scale, zp)
	}
	for _, v := range q {
		if v != 255 {
			t.Fatalf("q = %v, want 255 everywhere", q)
		}
	}
}

func TestMatmulSmall(t *testing.T) {
	m := &qmat{
		k:     2,
		n:     2,
		w:     []int8{1, 2, -1, 3}, // column 0 [1 2], column 1 [-1 3]
		scale: []float32{0.5, 0.25},
		zp:    []int32{0, 1},
		sum:   []int32{3, 2},
	}
	x := []float32{2, -1}
	out := m.matmul(x, 1, 1)

	q, xs, xz := quant(x)
	for c := 0; c < m.n; c++ {
		var acc int32
		for i := 0; i < m.k; i++ {
			acc += (int32(q[i]) - xz) * (int32(m.w[c*m.k+i]) - m.zp[c])
		}
		want := float32(acc) * xs * m.scale[c]
		if math.Abs(float64(out[c]-want)) > 1e-6 {
			t.Fatalf("out[%d] = %v, want %v", c, out[c], want)
		}
	}

	// Two rows get independent input quantization in matmul; check the
	// second row against the same formula.
	x2 := []float32{0, 4}
	out2 := m.matmul(x2, 1, 1)
	q2, xs2, xz2 := quant(x2)
	for c := 0; c < m.n; c++ {
		var acc int32
		for i := 0; i < m.k; i++ {
			acc += (int32(q2[i]) - xz2) * (int32(m.w[c*m.k+i]) - m.zp[c])
		}
		want := float32(acc) * xs2 * m.scale[c]
		if math.Abs(float64(out2[c]-want)) > 1e-6 {
			t.Fatalf("out2[%d] = %v, want %v", c, out2[c], want)
		}
	}
}

func TestDecodeBIO(t *testing.T) {
	toks := []token{
		{0, 0, 0},  // a lone ▁: no text, ignored
		{1, 0, 5},  // B-email
		{2, 5, 9},  // I-email
		{0, 9, 10}, // O
		{1, 10, 15},
		{1, 15, 20}, // B starts another span
		{1, 20, 25}, // B below floor, dropped
	}
	lab := []int{0, 1, 2, 0, 1, 2, 1}
	prob := []float64{1, 0.9, 0.8, 1, 0.7, 0.6, 0.4}
	got := decode(toks, lab, prob)
	if len(got) != 2 {
		t.Fatalf("spans = %+v, want 2", got)
	}
	if got[0].Start != 0 || got[0].End != 9 || got[0].Label != "email" || got[0].Score != 0.8 {
		t.Fatalf("span 0 = %+v", got[0])
	}
	if got[1].Start != 10 || got[1].End != 20 || got[1].Label != "email" || got[1].Score != 0.6 {
		t.Fatalf("span 1 = %+v", got[1])
	}
}

func TestDecodeKindChangeStartsNewSpan(t *testing.T) {
	toks := []token{{1, 0, 3}, {5, 3, 6}} // B-email then B-phone
	lab := []int{1, 3}
	prob := []float64{0.9, 0.9}
	got := decode(toks, lab, prob)
	if len(got) != 2 || got[0].Label != "email" || got[1].Label != "phone" {
		t.Fatalf("spans = %+v", got)
	}
}

func TestLayerNorm(t *testing.T) {
	full := make([]float32, hidden)
	copy(full, []float32{1, 2, 3})
	w := make([]float32, hidden)
	b := make([]float32, hidden)
	for i := range w {
		w[i] = 1
	}
	mean := float32(0)
	for _, v := range full {
		mean += v
	}
	mean /= hidden
	var vr float32
	for _, v := range full {
		vr += (v - mean) * (v - mean)
	}
	vr /= hidden
	inv := float32(1 / math.Sqrt(float64(vr)+1e-12))
	want := make([]float32, hidden)
	for i, v := range full {
		want[i] = (v - mean) * inv
	}
	layerNorm(full, 1, w, b)
	for i := range full {
		if math.Abs(float64(full[i]-want[i])) > 1e-5 {
			t.Fatalf("full[%d] = %v, want %v", i, full[i], want[i])
		}
	}
}

func TestGeluRow(t *testing.T) {
	row := []float32{0, 1}
	bias := []float32{0, 0}
	smooth := []float32{1, 1}
	geluRow(row, bias, smooth)
	if math.Abs(float64(row[0])) > 1e-6 {
		t.Fatalf("gelu(0) = %v", row[0])
	}
	want := 1 * float32(0.5*(1+math.Erf(1/math.Sqrt2)))
	if math.Abs(float64(row[1]-want)) > 1e-4 {
		t.Fatalf("gelu(1) = %v, want %v", row[1], want)
	}
}
