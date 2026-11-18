package docs_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/docs"
)

func render(t *testing.T, host string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	h := docs.Handler(docs.Options{MaxRequestBytes: 100 << 20, RatePerSec: 30, RateBurst: 30, MaxConcurrent: 20,
		ResponseHeaderTimeout: 60 * time.Second})
	req := httptest.NewRequest("GET", "/doc", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Result().Body)
	return rec, string(b)
}

func TestDocPageContent(t *testing.T) {
	rec, body := render(t, "50.118.186.212:13800")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("status %d ct %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, want := range []string{
		"http://50.118.186.212:13800/v1/relay", // examples use the address the reader used
		"X-Relay-Key", "X-Relay-Target", "X-Relay-Error", "X-Relay-Request-ID",
		"TARGET_FORBIDDEN", "AUTH_FAILED", "RATE_LIMITED", "UPSTREAM_TIMEOUT",
		"100.0 MiB", "30 次/秒", "20 个", "60s", // limits come from config
		"requests.post", "fetch(",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("doc page missing %q", want)
		}
	}
}

func TestDocPageSecurityHeaders(t *testing.T) {
	rec, _ := render(t, "relay.test")
	for k, v := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	} {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
}

func TestDocPageEscapesHost(t *testing.T) {
	_, body := render(t, `x"><script>alert(1)</script>`)
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("host header not escaped")
	}
}
