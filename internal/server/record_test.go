package server_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/server"
)

func TestRecordsRelayRequest(t *testing.T) {
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) { io.ReadAll(r.Body); io.WriteString(w, "hello world") }, mods{})
	resp := e.relayReq(t, "POST", "/p?token=QTOKEN", strings.NewReader(strings.Repeat("x", 1234)),
		map[string]string{"X-Forwarded-For": "203.0.113.9", "Authorization": "Bearer UPTOKEN"})
	io.ReadAll(resp.Body)
	recs := e.rec.wait(t, 1)
	time.Sleep(50 * time.Millisecond)
	if len(e.rec.all()) != 1 {
		t.Fatalf("got %d records", len(e.rec.all()))
	}
	r := recs[0]
	if r.KeyID != "alice" || r.Method != "POST" || r.TargetHost != "example.com" || r.Status != 200 ||
		r.BytesIn != 1234 || r.BytesOut != 11 || r.ClientIP != "203.0.113.9" ||
		r.RequestID != resp.Header.Get("X-Relay-Request-ID") || r.Duration <= 0 || r.Time.IsZero() || r.ErrorCode != "" {
		t.Fatalf("record %+v", r)
	}
	for _, s := range []string{r.RequestID, r.KeyID, r.ClientIP, r.Method, r.TargetHost, r.ErrorCode} {
		if strings.Contains(s, "S3CRET") || strings.Contains(s, "UPTOKEN") || strings.Contains(s, "QTOKEN") {
			t.Fatalf("record leaks secret: %+v", r)
		}
	}
}

func TestRecordsAuthFailure(t *testing.T) {
	e := newEnv(t, okUpstream, mods{})
	e.req(t, context.Background(), "GET", "/v1/relay", nil, http.Header{"X-Relay-Key": {"bad"}})
	r := e.rec.wait(t, 1)[0]
	if r.KeyID != "" || r.Status != 401 || r.ErrorCode != "AUTH_FAILED" {
		t.Fatalf("record %+v", r)
	}
}

func TestNotRecorded(t *testing.T) {
	e := newEnv(t, okUpstream, mods{})
	e.req(t, context.Background(), "GET", "/healthz", nil, nil)
	e.req(t, context.Background(), "GET", "/nope", nil, nil)
	e.req(t, context.Background(), "TRACE", "/v1/relay", nil, nil)
	time.Sleep(200 * time.Millisecond)
	if n := len(e.rec.all()); n != 0 {
		t.Fatalf("recorded %d", n)
	}
}

func TestUntrustedForwardedForIgnored(t *testing.T) {
	e := newEnv(t, okUpstream, mods{deps: func(d *server.Deps) { d.TrustedProxies = nil }})
	resp := e.relayReq(t, "GET", "/", nil, map[string]string{"X-Forwarded-For": "203.0.113.9"})
	io.ReadAll(resp.Body)
	if ip := e.rec.wait(t, 1)[0].ClientIP; ip != "127.0.0.1" {
		t.Fatalf("ClientIP %q", ip)
	}
}

func TestNilRecorder(t *testing.T) {
	e := newEnv(t, okUpstream, mods{deps: func(d *server.Deps) { d.Recorder = nil }})
	if resp := e.relayReq(t, "GET", "/", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
