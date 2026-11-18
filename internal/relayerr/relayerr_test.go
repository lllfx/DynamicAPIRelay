package relayerr_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"

	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
)

func TestCodeStatus(t *testing.T) {
	cases := map[relayerr.Code]int{
		relayerr.TargetInvalid: 400, relayerr.RequestInvalid: 400, relayerr.AuthFailed: 401,
		relayerr.TargetForbidden: 403, relayerr.NotFound: 404, relayerr.MethodNotAllowed: 405,
		relayerr.RequestTooLarge: 413, relayerr.RateLimited: 429, relayerr.ConcurrencyLimited: 429,
		relayerr.Internal: 500, relayerr.UpstreamConnectFailed: 502, relayerr.UpstreamProtocolError: 502,
		relayerr.UpstreamTimeout: 504,
	}
	for c, want := range cases {
		if got := c.Status(); got != want {
			t.Errorf("%s: got %d want %d", c, got, want)
		}
		if relayerr.New(c).Message == "" {
			t.Errorf("%s: empty default message", c)
		}
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	relayerr.Write(rec, "req_abc", relayerr.New(relayerr.TargetForbidden))
	if rec.Code != 403 {
		t.Fatalf("status %d", rec.Code)
	}
	h := rec.Header()
	checks := map[string]string{
		"X-Relay-Error":      "true",
		"X-Relay-Request-ID": "req_abc",
		"Content-Type":       "application/json; charset=utf-8",
		"Cache-Control":      "no-store",
	}
	for k, v := range checks {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q want %q", k, got, v)
		}
	}
	var got, want any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(`{"error":{"code":"TARGET_FORBIDDEN","message":"Destination is not allowed","request_id":"req_abc"}}`), &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("body %s", rec.Body.String())
	}
}

func TestAuthFailedMessage(t *testing.T) {
	if m := relayerr.New(relayerr.AuthFailed).Message; m != "Relay authentication failed" {
		t.Errorf("got %q", m)
	}
}

func TestNewRequestID(t *testing.T) {
	re := regexp.MustCompile(`^req_[0-9a-f]{32}$`)
	a, b := relayerr.NewRequestID(), relayerr.NewRequestID()
	if !re.MatchString(a) || !re.MatchString(b) || a == b {
		t.Errorf("bad ids %q %q", a, b)
	}
}
