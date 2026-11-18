package server_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/limiter"
	"github.com/lllfx/DynamicAPIRelay/internal/relay"
	"github.com/lllfx/DynamicAPIRelay/internal/server"
)

func okUpstream(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello world") }

func TestHealthz(t *testing.T) {
	e := newEnv(t, okUpstream, mods{})
	resp := e.req(t, context.Background(), "GET", "/healthz", nil, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok"`) {
		t.Fatalf("status %d body %s", resp.StatusCode, b)
	}
}

func TestAuthFailsBeforeDNS(t *testing.T) {
	e := newEnv(t, okUpstream, mods{})
	target := e.up.BaseURL + "/"
	cases := []http.Header{
		{"X-Relay-Target": {target}},
		{"X-Relay-Target": {target}, "X-Relay-Key": {"wrong"}},
		{"X-Relay-Target": {target}, "X-Relay-Key": {aliceKey, aliceKey}},
	}
	for i, h := range cases {
		resp := e.req(t, context.Background(), "GET", "/v1/relay", nil, h)
		if resp.StatusCode != 401 || resp.Header.Get("X-Relay-Error") != "true" {
			t.Fatalf("case %d: status %d", i, resp.StatusCode)
		}
		if code, msg := errCode(t, resp); code != "AUTH_FAILED" || msg != "Relay authentication failed" {
			t.Fatalf("case %d: %s %s", i, code, msg)
		}
	}
	if n := e.up.Resolver.Calls.Load(); n != 0 {
		t.Fatalf("resolver called %d times", n)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	e := newEnv(t, okUpstream, mods{})
	for _, m := range []string{"TRACE", "OPTIONS", "PROPFIND"} {
		resp := e.req(t, context.Background(), m, "/v1/relay", nil, http.Header{"X-Relay-Key": {aliceKey}})
		if resp.StatusCode != 405 {
			t.Fatalf("%s: status %d", m, resp.StatusCode)
		}
		if code, _ := errCode(t, resp); code != "METHOD_NOT_ALLOWED" {
			t.Fatalf("%s: code %s", m, code)
		}
	}
}

func TestAmbiguousPaths(t *testing.T) {
	e := newEnv(t, okUpstream, mods{})
	h := http.Header{"X-Relay-Key": {aliceKey}, "X-Relay-Target": {e.up.BaseURL + "/"}}
	for path, want := range map[string]int{
		"/v1/relay?x=1": 400, "/v1/relay?": 400, "/v1/%72elay": 400, "/v1/relay/": 404, "/v1//relay": 404,
	} {
		resp := e.req(t, context.Background(), "GET", path, nil, h)
		if resp.StatusCode != want {
			t.Fatalf("%s: status %d want %d", path, resp.StatusCode, want)
		}
		wantCode := map[int]string{400: "REQUEST_INVALID", 404: "NOT_FOUND"}[want]
		if code, _ := errCode(t, resp); code != wantCode {
			t.Fatalf("%s: code %s", path, code)
		}
	}
}

func TestEndToEndSuccess(t *testing.T) {
	e := newEnv(t, okUpstream, mods{})
	resp := e.relayReq(t, "GET", "/x", nil, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "hello world" || !strings.HasPrefix(resp.Header.Get("X-Relay-Request-ID"), "req_") {
		t.Fatalf("status %d body %q hdr %v", resp.StatusCode, b, resp.Header)
	}
}

func TestRateLimited(t *testing.T) {
	e := newEnv(t, okUpstream, mods{deps: func(d *server.Deps) { d.Limiter = limiter.New(1, 1, 10) }})
	e.relayReq(t, "GET", "/", nil, nil)
	resp := e.relayReq(t, "GET", "/", nil, nil)
	if code, _ := errCode(t, resp); resp.StatusCode != 429 || code != "RATE_LIMITED" {
		t.Fatalf("status %d code %s", resp.StatusCode, code)
	}
}

func TestClientDisconnectReleasesSlot(t *testing.T) {
	upCanceled := make(chan struct{})
	up := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sse" {
			io.WriteString(w, "ok")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: 1\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(upCanceled)
	}
	e := newEnv(t, up, mods{deps: func(d *server.Deps) { d.Limiter = limiter.New(100, 100, 1) }})
	ctx, cancel := context.WithCancel(context.Background())
	resp := e.req(t, ctx, "GET", "/v1/relay", nil, http.Header{"X-Relay-Key": {aliceKey}, "X-Relay-Target": {e.up.BaseURL + "/sse"}})
	if line, _ := bufio.NewReader(resp.Body).ReadString('\n'); line != "data: 1\n" {
		t.Fatalf("first line %q", line)
	}
	cancel()
	select {
	case <-upCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream not canceled")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		r := e.relayReq(t, "GET", "/", nil, nil)
		if r.StatusCode == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot never released, last status %d", r.StatusCode)
		}
		time.Sleep(20 * time.Millisecond)
	}
	found := false
	for _, r := range e.rec.wait(t, 2) {
		found = found || r.ClientCanceled
	}
	if !found {
		t.Fatal("no record with ClientCanceled")
	}
}

func TestMidStreamAbortNoStackTrace(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 10; i++ {
			io.WriteString(w, "0123456789")
			w.(http.Flusher).Flush()
		}
	}
	e := newEnv(t, up, mods{relay: func(o *relay.Options) { o.MaxResponseBytes = 10 }})
	resp := e.relayReq(t, "GET", "/", nil, nil)
	b, err := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || (err == nil && len(b) >= 100) {
		t.Fatalf("status %d len %d err %v", resp.StatusCode, len(b), err)
	}
	recs := e.rec.wait(t, 1)
	if !recs[0].Aborted {
		t.Fatalf("record not marked aborted: %+v", recs[0])
	}
	if logs := e.logs.String(); strings.Contains(logs, "INTERNAL_ERROR") || strings.Contains(logs, "goroutine") {
		t.Fatalf("unexpected logs: %s", logs)
	}
}

func TestLogsContainNoSecrets(t *testing.T) {
	e := newEnv(t, okUpstream, mods{})
	resp := e.relayReq(t, "GET", "/p?token=QTOKEN", nil, map[string]string{"Authorization": "Bearer UPTOKEN"})
	io.ReadAll(resp.Body)
	e.rec.wait(t, 1)
	logs := e.logs.String()
	for _, s := range []string{"S3CRET", "UPTOKEN", "QTOKEN"} {
		if strings.Contains(logs, s) {
			t.Fatalf("log leaks %s: %s", s, logs)
		}
	}
	if !strings.Contains(logs, `"key_id":"alice"`) || !strings.Contains(logs, `"target_host":"example.com"`) {
		t.Fatalf("missing fields: %s", logs)
	}
}
