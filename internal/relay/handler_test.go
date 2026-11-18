package relay_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/relay"
	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
	"github.com/lllfx/DynamicAPIRelay/internal/relaytest"
	"github.com/lllfx/DynamicAPIRelay/internal/reqctx"
	"github.com/lllfx/DynamicAPIRelay/internal/transport"
)

type harness struct {
	up   *relaytest.Upstream
	srv  *httptest.Server
	last atomic.Pointer[reqctx.Info]
}

func newHarness(t *testing.T, upstream http.HandlerFunc, mod func(*relay.Options, *relaytest.Upstream)) *harness {
	t.Helper()
	h := &harness{up: relaytest.NewUpstream(t, upstream)}
	opts := relay.Options{Transport: h.up.Transport, Policy: h.up.Policy, MaxRequestBytes: 1 << 20}
	if mod != nil {
		mod(&opts, h.up)
	}
	rh := relay.New(opts)
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := &reqctx.Info{RequestID: "req_test"}
		h.last.Store(info)
		rh.ServeHTTP(w, r.WithContext(reqctx.With(r.Context(), info)))
	}))
	t.Cleanup(h.srv.Close)
	return h
}

var client = &http.Client{
	Transport:     &http.Transport{DisableCompression: true},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (h *harness) do(t *testing.T, method, target string, body io.Reader, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+"/v1/relay", body)
	if err != nil {
		t.Fatal(err)
	}
	if target != "" {
		req.Header.Set("X-Relay-Target", target)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func wantRelayError(t *testing.T, resp *http.Response, status int, code relayerr.Code) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status %d want %d", resp.StatusCode, status)
	}
	if resp.Header.Get("X-Relay-Error") != "true" {
		t.Fatalf("missing X-Relay-Error")
	}
	var body struct{ Error struct{ Code string } }
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != string(code) {
		t.Fatalf("code %q want %q", body.Error.Code, code)
	}
}

func TestForwardsMethodBodyAndHeaders(t *testing.T) {
	type seen struct {
		method, path, query, host, body string
		hdr                             http.Header
	}
	ch := make(chan seen, 1)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Host, string(b), r.Header.Clone()}
	}, nil)
	resp := h.do(t, "POST", h.up.BaseURL+"/v1/messages?mode=test", strings.NewReader(`{"hello":"world"}`), map[string]string{
		"Authorization": "Bearer up", "X-Relay-Key": "secretkey", "X-Relay-Foo": "x",
		"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "1.2.3.4", "Content-Type": "application/json",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	s := <-ch
	if s.method != "POST" || s.path != "/v1/messages" || s.query != "mode=test" || s.body != `{"hello":"world"}` ||
		s.host != "example.com:"+h.up.Port {
		t.Errorf("unexpected upstream view: %+v", s)
	}
	if s.hdr.Get("Authorization") != "Bearer up" || s.hdr.Get("Content-Type") != "application/json" {
		t.Errorf("end-to-end headers lost: %v", s.hdr)
	}
	for k := range s.hdr {
		if strings.HasPrefix(k, "X-Relay-") || k == "X-Forwarded-For" || k == "X-Real-Ip" || k == "Forwarded" {
			t.Errorf("header %s leaked upstream", k)
		}
	}
}

func TestReturnsUpstreamStatusAndHeaders(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(401)
		io.WriteString(w, "nope")
	}, nil)
	resp := h.do(t, "GET", h.up.BaseURL+"/", nil, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 401 || resp.Header.Get("X-Relay-Error") != "" || resp.Header.Get("ETag") != `"abc"` ||
		resp.Header.Get("X-Relay-Request-ID") != "req_test" || string(b) != "nope" {
		t.Errorf("status=%d hdr=%v body=%q", resp.StatusCode, resp.Header, b)
	}
}

func TestUpstreamRelayHeadersStripped(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Relay-Error", "true")
		w.Header().Set("X-Relay-Request-ID", "forged")
	}, nil)
	resp := h.do(t, "GET", h.up.BaseURL+"/", nil, nil)
	if resp.Header.Get("X-Relay-Error") != "" || len(resp.Header.Values("X-Relay-Request-ID")) != 1 ||
		resp.Header.Get("X-Relay-Request-ID") != "req_test" {
		t.Errorf("headers %v", resp.Header)
	}
}

func TestRawPathAndQueryPreserved(t *testing.T) {
	ch := make(chan [2]string, 1)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		ch <- [2]string{r.URL.EscapedPath(), r.URL.RawQuery}
	}, nil)
	h.do(t, "GET", h.up.BaseURL+"/a%2Fb/c?sig=a+b%20c&x=%3D", nil, nil)
	if got := <-ch; got != [2]string{"/a%2Fb/c", "sig=a+b%20c&x=%3D"} {
		t.Errorf("got %v", got)
	}
}

func TestNoRedirectFollow(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://other.example/")
		w.WriteHeader(302)
	}, nil)
	resp := h.do(t, "GET", h.up.BaseURL+"/", nil, nil)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "https://other.example/" {
		t.Errorf("status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestNoSilentDecompression(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("hello hello hello"))
	zw.Close()
	sawAE := make(chan string, 2)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		sawAE <- r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz.Bytes())
	}, nil)
	resp := h.do(t, "GET", h.up.BaseURL+"/", nil, map[string]string{"Accept-Encoding": "gzip"})
	b, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(b, gz.Bytes()) || resp.Header.Get("Content-Encoding") != "gzip" || <-sawAE != "gzip" {
		t.Errorf("body or encoding altered")
	}
	h.do(t, "GET", h.up.BaseURL+"/", nil, nil)
	if ae := <-sawAE; ae != "" {
		t.Errorf("relay added Accept-Encoding %q", ae)
	}
}

func TestHeadNoBody(t *testing.T) {
	ch := make(chan string, 1)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		ch <- r.Method
		w.Header().Set("Content-Length", "5")
	}, nil)
	resp := h.do(t, "HEAD", h.up.BaseURL+"/", nil, nil)
	b, _ := io.ReadAll(resp.Body)
	if <-ch != "HEAD" || len(b) != 0 || resp.StatusCode != 200 {
		t.Errorf("status=%d body=%q", resp.StatusCode, b)
	}
}

func TestSSEStreamsIncrementally(t *testing.T) {
	gotFirst := make(chan struct{})
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: 1\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-gotFirst:
		case <-time.After(2 * time.Second):
			return
		}
		io.WriteString(w, "data: 2\n\n")
	}, nil)
	resp := h.do(t, "POST", h.up.BaseURL+"/stream", strings.NewReader(`{"stream":true}`), nil)
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: 1\n" {
		t.Fatalf("first event %q %v", line, err)
	}
	close(gotFirst)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: 2") {
		t.Errorf("rest %q", rest)
	}
}

func TestMissingTargetHeader(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, nil)
	wantRelayError(t, h.do(t, "GET", "", nil, nil), 400, relayerr.TargetInvalid)
}

func TestDuplicateTargetHeader(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, nil)
	req, _ := http.NewRequest("GET", h.srv.URL+"/v1/relay", nil)
	req.Header.Add("X-Relay-Target", h.up.BaseURL+"/a")
	req.Header.Add("X-Relay-Target", h.up.BaseURL+"/b")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	wantRelayError(t, resp, 400, relayerr.RequestInvalid)
	if n := h.up.Resolver.Calls.Load(); n != 0 {
		t.Errorf("resolver called %d times", n)
	}
	if h.last.Load().ErrorCode != relayerr.RequestInvalid {
		t.Errorf("info.ErrorCode not set")
	}
}

func TestInvalidTargetForbidden(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, nil)
	wantRelayError(t, h.do(t, "GET", "http://example.com/", nil, nil), 403, relayerr.TargetForbidden)
}

func TestRequestTooLarge(t *testing.T) {
	mod := func(o *relay.Options, _ *relaytest.Upstream) { o.MaxRequestBytes = 10 }
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { io.ReadAll(r.Body) }, mod)
	wantRelayError(t, h.do(t, "POST", h.up.BaseURL+"/", strings.NewReader("01234567890"), nil), 413, relayerr.RequestTooLarge)
	chunked := io.MultiReader(strings.NewReader("012345"), strings.NewReader("67890"))
	wantRelayError(t, h.do(t, "POST", h.up.BaseURL+"/", chunked, nil), 413, relayerr.RequestTooLarge)
}

func TestResponseTooLargeByContentLength(t *testing.T) {
	mod := func(o *relay.Options, _ *relaytest.Upstream) { o.MaxResponseBytes = 10 }
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "01234567890") }, mod)
	wantRelayError(t, h.do(t, "GET", h.up.BaseURL+"/", nil, nil), 502, relayerr.UpstreamProtocolError)
}

func TestTLSHostnameMismatch(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, nil)
	wantRelayError(t, h.do(t, "GET", "https://evil.test:"+h.up.Port+"/", nil, nil), 502, relayerr.UpstreamConnectFailed)
}

func TestUnknownHostConnectFailed(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, nil)
	wantRelayError(t, h.do(t, "GET", "https://nx.example:"+h.up.Port+"/", nil, nil), 502, relayerr.UpstreamConnectFailed)
}

func TestForbiddenResolution(t *testing.T) {
	mod := func(o *relay.Options, up *relaytest.Upstream) { o.Transport = up.NewTransport(transport.Options{}) }
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, mod)
	wantRelayError(t, h.do(t, "GET", h.up.BaseURL+"/", nil, nil), 403, relayerr.TargetForbidden)
}

func TestResponseHeaderTimeout(t *testing.T) {
	mod := func(o *relay.Options, up *relaytest.Upstream) {
		o.Transport = up.NewTransport(transport.Options{
			AllowIP:               func(a netipAddr) bool { return true },
			ResponseHeaderTimeout: 100 * time.Millisecond,
		})
	}
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}, mod)
	wantRelayError(t, h.do(t, "GET", h.up.BaseURL+"/", nil, nil), 504, relayerr.UpstreamTimeout)
}

func TestCountsBytesIn(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) { io.ReadAll(r.Body) }, nil)
	resp := h.do(t, "POST", h.up.BaseURL+"/", bytes.NewReader(make([]byte, 1234)), nil)
	io.ReadAll(resp.Body)
	info := h.last.Load()
	if got := atomicLoad(&info.BytesIn); got != 1234 {
		t.Errorf("BytesIn=%d", got)
	}
	if info.TargetHost != "example.com" {
		t.Errorf("TargetHost=%q", info.TargetHost)
	}
}
