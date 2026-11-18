// Package docs serves the client usage guide at /doc.
package docs

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

//go:embed doc.html
var page string

var tmpl = template.Must(template.New("doc").Parse(page))

// Options are the live limits shown on the page.
type Options struct {
	MaxRequestBytes       int64
	RatePerSec            float64
	RateBurst             int
	MaxConcurrent         int
	ResponseHeaderTimeout time.Duration
}

type view struct {
	Base, Host            string
	MaxBody               string
	Rate                  string
	Burst, Concurrent     int
	ResponseHeaderTimeout string
}

// Handler renders the guide. Examples use the scheme and host the reader used.
func Handler(opts Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		v := view{
			Base:                  scheme + "://" + r.Host,
			Host:                  r.Host,
			MaxBody:               formatBytes(opts.MaxRequestBytes),
			Rate:                  fmt.Sprintf("%g 次/秒", opts.RatePerSec),
			Burst:                 opts.RateBurst,
			Concurrent:            opts.MaxConcurrent,
			ResponseHeaderTimeout: formatDur(opts.ResponseHeaderTimeout),
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-cache")
		_ = tmpl.Execute(w, v)
	}
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func formatDur(d time.Duration) string {
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", int64(d/time.Second))
	}
	return d.String()
}
