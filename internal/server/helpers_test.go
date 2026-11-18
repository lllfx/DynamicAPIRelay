package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/auth"
	"github.com/lllfx/DynamicAPIRelay/internal/limiter"
	"github.com/lllfx/DynamicAPIRelay/internal/relay"
	"github.com/lllfx/DynamicAPIRelay/internal/relaytest"
	"github.com/lllfx/DynamicAPIRelay/internal/server"
	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

const aliceKey = "S3CRETS3CRETS3CRETS3CRETS3CRET00"

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type fakeRecorder struct {
	mu   sync.Mutex
	recs []stats.Record
}

func (f *fakeRecorder) Record(r stats.Record) { f.mu.Lock(); f.recs = append(f.recs, r); f.mu.Unlock() }

func (f *fakeRecorder) all() []stats.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]stats.Record(nil), f.recs...)
}

func (f *fakeRecorder) wait(t *testing.T, n int) []stats.Record {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if r := f.all(); len(r) >= n {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d records, want %d", len(f.all()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type env struct {
	up   *relaytest.Upstream
	srv  *httptest.Server
	logs *syncBuf
	rec  *fakeRecorder
}

type mods struct {
	deps  func(*server.Deps)
	relay func(*relay.Options)
}

func newEnv(t *testing.T, upstream http.HandlerFunc, m mods) *env {
	t.Helper()
	e := &env{up: relaytest.NewUpstream(t, upstream), logs: &syncBuf{}, rec: &fakeRecorder{}}
	logger := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ro := relay.Options{Transport: e.up.Transport, Policy: e.up.Policy, MaxRequestBytes: 1 << 20, Logger: logger}
	if m.relay != nil {
		m.relay(&ro)
	}
	d := server.Deps{
		Auth:           auth.NewKeyStore(map[string]string{"alice": aliceKey}),
		Limiter:        limiter.New(1000, 1000, 100),
		Relay:          relay.New(ro),
		Logger:         logger,
		Recorder:       e.rec,
		TrustedProxies: []string{"127.0.0.1/32"},
	}
	if m.deps != nil {
		m.deps(&d)
	}
	router, err := server.NewRouter(d)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(router)
	t.Cleanup(e.srv.Close)
	return e
}

var client = &http.Client{
	Transport:     &http.Transport{DisableCompression: true},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (e *env) req(t *testing.T, ctx context.Context, method, path string, body io.Reader, hdr http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, e.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// relayReq sends an authenticated relay request to target path on the upstream.
func (e *env) relayReq(t *testing.T, method, targetPath string, body io.Reader, extra map[string]string) *http.Response {
	h := http.Header{"X-Relay-Key": {aliceKey}, "X-Relay-Target": {e.up.BaseURL + targetPath}}
	for k, v := range extra {
		h.Set(k, v)
	}
	return e.req(t, context.Background(), method, "/v1/relay", body, h)
}

func errCode(t *testing.T, resp *http.Response) (code, message string) {
	t.Helper()
	var b struct {
		Error struct{ Code, Message string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return b.Error.Code, b.Error.Message
}
