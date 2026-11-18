// Package dashboard serves the read-only usage and error dashboard.
package dashboard

import (
	"crypto/subtle"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

//go:embed templates/*.html
var templateFS embed.FS

// Options configures New.
type Options struct {
	Store         *stats.Store
	Dropped       func() int64 // nil → 0
	KeyIDs        []string     // configured key IDs (never secrets)
	Location      *time.Location
	Password      string // non-empty enables Basic auth with user "admin"
	RetentionDays int
	Now           func() time.Time // nil → time.Now
	Logger        *slog.Logger
}

const (
	unauthLabel  = "(未鉴权)"
	failuresPage = 50
	topHosts     = 20
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type rangeSpec struct {
	Name  string
	Label string
	Span  time.Duration
	Step  time.Duration
}

var ranges = []rangeSpec{
	{"24h", "24小时", 24 * time.Hour, time.Hour},
	{"7d", "7天", 7 * 24 * time.Hour, 24 * time.Hour},
	{"30d", "30天", 30 * 24 * time.Hour, 24 * time.Hour},
}

func parseRange(v string) rangeSpec {
	for _, r := range ranges {
		if r.Name == v {
			return r
		}
	}
	return ranges[0]
}

type dash struct {
	opts     Options
	overview *template.Template
	key      *template.Template
}

// New returns the dashboard handler.
func New(opts Options) http.Handler {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Location == nil {
		opts.Location = time.UTC
	}
	if opts.Dropped == nil {
		opts.Dropped = func() int64 { return 0 }
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	d := &dash{opts: opts}
	funcs := template.FuncMap{
		"num": formatNum, "bytes": formatBytes, "rate": formatRate, "dur": formatDur,
		"svg": trendSVG,
		"add": func(a, b int) int { return a + b },
		"pct": func(n, d int64) string {
			if d == 0 {
				return "—"
			}
			return fmt.Sprintf("%.1f%%", float64(n)/float64(d)*100)
		},
		"ts": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.In(opts.Location).Format("01-02 15:04:05")
		},
	}
	parse := func(page string) *template.Template {
		return template.Must(template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+page))
	}
	d.overview, d.key = parse("overview.html"), parse("key.html")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.handleOverview)
	mux.HandleFunc("GET /keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !keyIDPattern.MatchString(id) {
			http.NotFound(w, r)
			return
		}
		d.handleKey(w, r, id)
	})
	mux.HandleFunc("GET /unauthenticated", func(w http.ResponseWriter, r *http.Request) { d.handleKey(w, r, "") })
	return d.wrap(mux)
}

func (d *dash) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
		if d.opts.Password != "" {
			user, pass, ok := r.BasicAuth()
			userOK := subtle.ConstantTimeCompare([]byte(user), []byte("admin")) == 1
			passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(d.opts.Password)) == 1
			if !ok || !userOK || !passOK {
				h.Set("WWW-Authenticate", `Basic realm="relay-dashboard", charset="UTF-8"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type pageBase struct {
	Title         string
	Range         rangeSpec
	Ranges        []rangeSpec
	BasePath      string
	Dropped       int64
	RetentionDays int
	Trend         []stats.Bucket
}

type keyRow struct {
	Label, Href string
	stats.Totals
}

type overviewPage struct {
	pageBase
	Total         stats.Totals
	ActiveClients int
	Rows          []keyRow
}

type keyPage struct {
	pageBase
	Label           string
	Totals          stats.Totals
	Hosts           []stats.HostStat
	Codes, Statuses []stats.LabelCount
	Failures        []stats.Failure
	NextHref        string
}

func (d *dash) base(r *http.Request, title, basePath string) (pageBase, stats.Range) {
	rs := parseRange(r.URL.Query().Get("range"))
	now := d.opts.Now()
	return pageBase{
		Title: title, Range: rs, Ranges: ranges, BasePath: basePath,
		Dropped: d.opts.Dropped(), RetentionDays: d.opts.RetentionDays,
	}, stats.Range{From: now.Add(-rs.Span), To: now}
}

func keyLink(id string) (label, href string) {
	if id == "" {
		return unauthLabel, "/unauthenticated"
	}
	return id, "/keys/" + url.PathEscape(id)
}

func (d *dash) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, rg := d.base(r, "DynamicAPIRelay 用量看板", "/")
	sums, err := d.opts.Store.Summaries(ctx, rg)
	if err != nil {
		d.fail(w, err)
		return
	}
	seen := map[string]bool{}
	page := overviewPage{pageBase: p}
	for _, s := range sums {
		seen[s.KeyID] = true
		label, href := keyLink(s.KeyID)
		page.Rows = append(page.Rows, keyRow{Label: label, Href: href, Totals: s.Totals})
		page.Total.Requests += s.Requests
		page.Total.Success += s.Success
		page.Total.UpstreamErrors += s.UpstreamErrors
		page.Total.Aborted += s.Aborted
		page.Total.RelayErrors += s.RelayErrors
		page.Total.ClientCanceled += s.ClientCanceled
		page.Total.BytesIn += s.BytesIn
		page.Total.BytesOut += s.BytesOut
		if s.KeyID != "" && s.Requests > 0 {
			page.ActiveClients++
		}
	}
	idle := []string{}
	for _, id := range d.opts.KeyIDs {
		if !seen[id] {
			idle = append(idle, id)
		}
	}
	sort.Strings(idle)
	for _, id := range idle {
		label, href := keyLink(id)
		page.Rows = append(page.Rows, keyRow{Label: label, Href: href})
	}
	if page.Trend, err = d.opts.Store.Trend(ctx, nil, rg, p.Range.Step, d.opts.Location); err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, d.overview, page)
}

func (d *dash) handleKey(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	label, href := keyLink(id)
	p, rg := d.base(r, label+" · DynamicAPIRelay", href)
	page := keyPage{pageBase: p, Label: label}
	var err error
	if page.Totals, err = d.opts.Store.KeyTotals(ctx, id, rg); err != nil {
		d.fail(w, err)
		return
	}
	if page.Trend, err = d.opts.Store.Trend(ctx, &id, rg, p.Range.Step, d.opts.Location); err != nil {
		d.fail(w, err)
		return
	}
	if page.Hosts, err = d.opts.Store.TopHosts(ctx, id, rg, topHosts); err != nil {
		d.fail(w, err)
		return
	}
	if page.Codes, page.Statuses, err = d.opts.Store.ErrorBreakdown(ctx, id, rg); err != nil {
		d.fail(w, err)
		return
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	if page.Failures, err = d.opts.Store.RecentFailures(ctx, id, rg, before, failuresPage); err != nil {
		d.fail(w, err)
		return
	}
	if len(page.Failures) == failuresPage {
		last := page.Failures[len(page.Failures)-1].ID
		page.NextHref = fmt.Sprintf("%s?range=%s&before=%d", href, p.Range.Name, last)
	}
	d.render(w, d.key, page)
}

func (d *dash) render(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", data); err != nil {
		d.opts.Logger.Error("dashboard render failed", "error", err)
	}
}

func (d *dash) fail(w http.ResponseWriter, err error) {
	d.opts.Logger.Error("dashboard query failed", "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func formatNum(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := n < 0
	if neg {
		s = s[1:]
	}
	var out []byte
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
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

func formatRate(c stats.Counts) string {
	r, ok := c.ErrorRate()
	if !ok {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", r*100)
}

func formatDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
