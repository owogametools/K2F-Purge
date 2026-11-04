// Derived from yetone/magpie (MIT), Copyright (c) 2026 yetone.
// Source: internal/pii/guard/kernel.go at
// 1a67ca614ed6a8180eaf6ea0442dd1272e43d603, without the amd64/arm64
// assembly kernels. These are the pure-Go paths magpie uses on any other
// CPU; their arithmetic order, and so their bits, are unchanged.

package astrlink

import (
	"math"
	"sync"
)

// dot4 sets out[j] to the dot product of a with
// b[j*len(a):(j+1)*len(a)].
func dot4(a, b []int8, out *[4]int32) {
	k := len(a)
	for j := range out {
		out[j] = dot(a, b[j*k:j*k+k])
	}
}

func dot(a, b []int8) int32 {
	b = b[:len(a)]
	var s0, s1, s2, s3 int32
	i := 0
	for ; i+4 <= len(a); i += 4 {
		s0 += int32(a[i]) * int32(b[i])
		s1 += int32(a[i+1]) * int32(b[i+1])
		s2 += int32(a[i+2]) * int32(b[i+2])
		s3 += int32(a[i+3]) * int32(b[i+3])
	}
	for ; i < len(a); i++ {
		s0 += int32(a[i]) * int32(b[i])
	}
	return s0 + s1 + s2 + s3
}

// dot32 is a·b for one attention head's rows.
func dot32(a, b *[32]float32) float32 {
	var s0, s1, s2, s3 float32
	for i := 0; i < 32; i += 4 {
		s0 += a[i] * b[i]
		s1 += a[i+1] * b[i+1]
		s2 += a[i+2] * b[i+2]
		s3 += a[i+3] * b[i+3]
	}
	return (s0 + s1) + (s2 + s3)
}

// axpy32 adds w·v to c.
func axpy32(c *[32]float32, w float32, v *[32]float32) {
	for i := range c {
		c[i] += w * v[i]
	}
}

// scores sets out[u] to Σ q[i]·kt[i*len(out)+u]: q against each key, with
// the keys transposed, len(out) of them (a multiple of 16).
func scores(q *[32]float32, kt []float32, out []float32) {
	np := len(out)
	clear(out)
	for i, w := range q {
		row := kt[i*np : i*np+np]
		for u, x := range row {
			out[u] += w * x
		}
	}
}

// mix adds Σ p[u]·v[u] to c, for v's rows of 32.
func mix(c *[32]float32, p, v []float32) {
	for u, w := range p {
		axpy32(c, w, (*[32]float32)(v[u*32:]))
	}
}

// maxOf is the largest of p (-Inf for none), and rangeOf the smallest
// and largest of x and 0: what min and max over them give, but compared
// in a plain loop. The builtins' order of NaN and of -0 against +0 took
// a third of the model's time outside its matrix products. A NaN gives
// NaN as they do; where they would give -0 these may give +0, which
// neither caller tells apart (s-mx and 0-lo/scale come out the same).
func maxOf(p []float32) float32 {
	mx := float32(math.Inf(-1))
	for _, s := range p {
		if s > mx {
			mx = s
		} else if s != s {
			return s
		}
	}
	return mx
}

func rangeOf(x []float32) (lo, hi float32) {
	for _, v := range x {
		if v < lo {
			lo = v
		} else if v > hi {
			hi = v
		} else if v != v {
			return v, v
		}
	}
	return lo, hi
}

// expf is e^x in float32, to about an ulp (Cephes' expf), for the
// softmax's x ≤ 0 and the GELU's erf.
func expf(x float32) float32 {
	if x < -87.3 {
		return 0
	}
	if x > 88.7 {
		return float32(math.Inf(1))
	}
	n := float32(math.Floor(float64(x*1.44269504088896341 + 0.5)))
	x -= n * 0.693359375
	x -= n * -2.12194440e-4
	z := x * x
	y := ((((1.9875691500e-4*x+1.3981999507e-3)*x+8.3334519073e-3)*x+4.1665795894e-2)*x+1.6666665459e-1)*x + 5.0000001201e-1
	y = y*z + x + 1
	return math.Float32frombits(math.Float32bits(y) + uint32(int32(n))<<23)
}

// expSub sets p[u] to expf(p[u]-mx): a softmax row's exponentials.
func expSub(p []float32, mx float32) {
	for i := range p {
		p[i] = expf(p[i] - mx)
	}
}

// geluRow sets row[i] to gelu(row[i]+bias[i])·smooth[i]: the feed
// forward's activation.
func geluRow(row, bias, smooth []float32) {
	bias, smooth = bias[:len(row)], smooth[:len(row)]
	for i := range row {
		row[i] = gelu(row[i]+bias[i]) * smooth[i]
	}
}

// gelu is x·Φ(x), with erf from Abramowitz and Stegun 7.1.26 (absolute
// error under 1.5e-7, below float32's own at the values it meets).
func gelu(x float32) float32 {
	z := x * 0.70710678118654752
	a := z
	if a < 0 {
		a = -a
	}
	t := 1 / (1 + 0.3275911*a)
	e := 1 - (((((1.061405429*t-1.453152027)*t)+1.421413741)*t-0.284496736)*t+0.254829592)*t*expf(-a*a)
	if z < 0 {
		e = -e
	}
	return 0.5 * x * (1 + e)
}

// parallel calls f over [0, n) in t parts at once; a panic in one is
// carried and panicked again here once all have ended. model.go's find
// catches that panic and turns it into an error.
func parallel(t, n int, f func(a, b int)) {
	t = min(t, n)
	if t <= 1 {
		f(0, n)
		return
	}
	var wg sync.WaitGroup
	var c carried
	step := (n + t - 1) / t
	for a := 0; a < n; a += step {
		wg.Add(1)
		go func(a, b int) {
			defer wg.Done()
			defer c.catch()
			f(a, b)
		}(a, min(n, a+step))
	}
	wg.Wait()
	c.rethrow()
}

// carried is a panic from a goroutine, panicked again by rethrow on the
// goroutine that waited for them, where a recovery can catch it.
type carried struct {
	mu sync.Mutex
	p  *any
}

func (c *carried) catch() {
	if r := recover(); r != nil {
		c.mu.Lock()
		if c.p == nil {
			c.p = &r
		}
		c.mu.Unlock()
	}
}

func (c *carried) rethrow() {
	c.mu.Lock()
	p := c.p
	c.mu.Unlock()
	if p != nil {
		panic(*p)
	}
}

// load is the carried panic, or nil. model.go reports it as an error.
func (c *carried) load() *any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.p
}
