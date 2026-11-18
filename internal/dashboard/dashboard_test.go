package dashboard_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/dashboard"
	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

var now = time.Date(2026, 11, 18, 12, 30, 0, 0, time.UTC)

func newStore(t *testing.T) *stats.Store {
	t.Helper()
	s, err := stats.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func rec(key string, ago time.Duration, status int) stats.Record {
	return stats.Record{Time: now.Add(-ago), RequestID: "req_ok", KeyID: key, ClientIP: "203.0.113.9", Method: "GET",
		TargetHost: "api.example.com", Status: status, BytesOut: 100, Duration: 5 * time.Millisecond}
}

func put(t *testing.T, s *stats.Store, recs ...stats.Record) {
	t.Helper()
	if err := s.Insert(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
}

func handler(s *stats.Store, mod func(*dashboard.Options)) http.Handler {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	o := dashboard.Options{Store: s, KeyIDs: []string{"alice", "carol"}, Location: loc, RetentionDays: 30,
		Now: func() time.Time { return now }, Dropped: func() int64 { return 7 }}
	if mod != nil {
		mod(&o)
	}
	return dashboard.New(o)
}

func get(t *testing.T, h http.Handler, method, path string, setup func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if setup != nil {
		setup(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestOverviewListsKeys(t *testing.T) {
	s := newStore(t)
	relayErr := rec("alice", time.Hour, 502)
	relayErr.ErrorCode = "UPSTREAM_CONNECT_FAILED"
	put(t, s, rec("alice", time.Hour, 200), rec("alice", 2*time.Hour, 200), relayErr, rec("", time.Hour, 401))
	resp, body := get(t, handler(s, nil), "GET", "/", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("status %d ct %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for _, want := range []string{`href="/keys/alice`, "(未鉴权)", `href="/unauthenticated`, "carol", "<svg", "33.3%", "统计丢弃 7 条", "数据保留 30 天"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview missing %q", want)
		}
	}
}

func TestRangeSelection(t *testing.T) {
	s := newStore(t)
	put(t, s, rec("alice", 3*24*time.Hour, 200))
	h := handler(s, func(o *dashboard.Options) { o.KeyIDs = nil })
	_, b24 := get(t, h, "GET", "/?range=24h", nil)
	_, b7 := get(t, h, "GET", "/?range=7d", nil)
	_, bogus := get(t, h, "GET", "/?range=bogus", nil)
	if strings.Contains(b24, "/keys/alice") || !strings.Contains(b7, "/keys/alice") || strings.Contains(bogus, "/keys/alice") {
		t.Fatalf("range filtering wrong: 24h=%v 7d=%v bogus=%v",
			strings.Contains(b24, "/keys/alice"), strings.Contains(b7, "/keys/alice"), strings.Contains(bogus, "/keys/alice"))
	}
}

func TestKeyDetailFailures(t *testing.T) {
	s := newStore(t)
	f := rec("alice", time.Hour, 504)
	f.RequestID, f.ErrorCode = "req_fail1", "UPSTREAM_TIMEOUT"
	put(t, s, f, rec("alice", time.Hour, 200))
	resp, body := get(t, handler(s, nil), "GET", "/keys/alice", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"req_fail1", "api.example.com", "UPSTREAM_TIMEOUT", "<svg"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
}

var beforeRe = regexp.MustCompile(`href="(/keys/alice\?[^"]*before=\d+[^"]*)"`)

func TestKeyDetailPaging(t *testing.T) {
	s := newStore(t)
	var recs []stats.Record
	for i := 0; i < 60; i++ {
		r := rec("alice", time.Hour, 500)
		r.RequestID = fmt.Sprintf("req_%03d", i)
		recs = append(recs, r)
	}
	put(t, s, recs...)
	h := handler(s, nil)
	_, p1 := get(t, h, "GET", "/keys/alice?range=24h", nil)
	m := beforeRe.FindStringSubmatch(p1)
	if m == nil || !strings.Contains(p1, "更早") {
		t.Fatal("no next-page link on page 1")
	}
	_, p2 := get(t, h, "GET", strings.ReplaceAll(m[1], "&amp;", "&"), nil)
	if n := strings.Count(p2, "req_0"); n != 10 {
		t.Fatalf("page 2 rows %d", n)
	}
	if strings.Contains(p2, "更早") {
		t.Fatal("page 2 should not link further")
	}
}

func TestUnauthenticatedPage(t *testing.T) {
	s := newStore(t)
	f := rec("", time.Hour, 401)
	f.ErrorCode, f.RequestID = "AUTH_FAILED", "req_noauth"
	put(t, s, f)
	resp, body := get(t, handler(s, nil), "GET", "/unauthenticated", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "req_noauth") || !strings.Contains(body, "(未鉴权)") {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestInvalidKeyID(t *testing.T) {
	h := handler(newStore(t), nil)
	for _, p := range []string{"/keys/a%20b", "/keys/" + strings.Repeat("a", 65), "/nope"} {
		if resp, _ := get(t, h, "GET", p, nil); resp.StatusCode != 404 {
			t.Errorf("%s: status %d", p, resp.StatusCode)
		}
	}
	if resp, _ := get(t, h, "GET", "/keys/zed", nil); resp.StatusCode != 200 {
		t.Errorf("/keys/zed: status %d", resp.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := handler(newStore(t), nil)
	resp, _ := get(t, h, "GET", "/", nil)
	for k, v := range map[string]string{
		"Cache-Control": "no-store", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
		"Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'",
	} {
		if resp.Header.Get(k) != v {
			t.Errorf("%s = %q", k, resp.Header.Get(k))
		}
	}
	if resp, _ := get(t, h, "POST", "/", nil); resp.StatusCode != 405 {
		t.Errorf("POST status %d", resp.StatusCode)
	}
}

func TestBasicAuth(t *testing.T) {
	s := newStore(t)
	h := handler(s, func(o *dashboard.Options) { o.Password = "pw" })
	resp, _ := get(t, h, "GET", "/", nil)
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no creds: %d", resp.StatusCode)
	}
	if resp, _ := get(t, h, "GET", "/", func(r *http.Request) { r.SetBasicAuth("admin", "wrong") }); resp.StatusCode != 401 {
		t.Fatalf("wrong pw: %d", resp.StatusCode)
	}
	if resp, _ := get(t, h, "GET", "/", func(r *http.Request) { r.SetBasicAuth("root", "pw") }); resp.StatusCode != 401 {
		t.Fatalf("wrong user: %d", resp.StatusCode)
	}
	if resp, _ := get(t, h, "GET", "/", func(r *http.Request) { r.SetBasicAuth("admin", "pw") }); resp.StatusCode != 200 {
		t.Fatalf("good creds: %d", resp.StatusCode)
	}
	if resp, _ := get(t, handler(s, nil), "GET", "/", nil); resp.StatusCode != 200 {
		t.Fatalf("no password configured: %d", resp.StatusCode)
	}
}

func TestHTMLEscapes(t *testing.T) {
	s := newStore(t)
	f := rec("alice", time.Hour, 500)
	f.TargetHost = "<script>x</script>"
	put(t, s, f)
	_, body := get(t, handler(s, nil), "GET", "/keys/alice", nil)
	if strings.Contains(body, "<script>x") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("target host not escaped")
	}
}
