package appui

import (
	"github.com/egoist/mygo/ui"
	"github.com/egoist/mygo/ui/shader"
)

// grain is a static film grain and faint scanline texture. Keeping it static
// means no frame is scheduled for it: it costs one pass per repaint.
var grain = shader.MustCompile(`package main

func Fragment(dst vec4, pos vec2) vec4 {
	n := fract(sin(dot(pos, vec2(12.9898, 78.233))) * 43758.5453)
	line := step(0.5, fract(pos.y / 3.0))
	a := 0.008 + n*0.020 + line*0.004
	return vec4(a, a, a, a)
}
`)

func drawGrain(p *ui.Painter, r ui.Rect) {
	grain.Draw(p, r, shader.Options{})
}
