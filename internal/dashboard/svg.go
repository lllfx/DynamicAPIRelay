package dashboard

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

const (
	svgW, svgH = 720.0, 160.0
)

// series in stacking order (bottom to top); client cancels are not drawn.
var series = []struct {
	color string
	value func(stats.Counts) int64
}{
	{"#3fa66a", func(c stats.Counts) int64 { return c.Success }},
	{"#e0a526", func(c stats.Counts) int64 { return c.UpstreamErrors }},
	{"#8e6bd1", func(c stats.Counts) int64 { return c.Aborted }},
	{"#d64545", func(c stats.Counts) int64 { return c.RelayErrors }},
}

// trendSVG renders a stacked bar chart. Output contains only numbers and
// fixed colors (no user data), so returning template.HTML is safe.
func trendSVG(buckets []stats.Bucket) template.HTML {
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="trend" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" role="img" aria-label="trend">`, svgW, svgH)
	fmt.Fprintf(&b, `<line x1="0" y1="%.0f" x2="%.0f" y2="%.0f" stroke="#8888" stroke-width="1"/>`, svgH-0.5, svgW, svgH-0.5)
	var peak int64
	for _, bk := range buckets {
		var sum int64
		for _, s := range series {
			sum += s.value(bk.Counts)
		}
		peak = max(peak, sum)
	}
	if len(buckets) > 0 && peak > 0 {
		slot := svgW / float64(len(buckets))
		width := slot * 0.8
		for i, bk := range buckets {
			x := float64(i)*slot + slot*0.1
			y := svgH
			for _, s := range series {
				v := s.value(bk.Counts)
				if v == 0 {
					continue
				}
				h := float64(v) / float64(peak) * (svgH - 4)
				y -= h
				fmt.Fprintf(&b, `<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s"/>`, x, y, width, h, s.color)
			}
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}
