// Package relay forwards an authenticated request to the URL named in
// X-Relay-Target using a shared reverse proxy and guarded transport.
package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/policy"
	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
	"github.com/lllfx/DynamicAPIRelay/internal/reqctx"
	"github.com/lllfx/DynamicAPIRelay/internal/transport"
)

// HeaderTarget carries the absolute upstream URL.
const HeaderTarget = "X-Relay-Target"

// Options configures New.
type Options struct {
	Transport          http.RoundTripper
	Policy             policy.TargetPolicy
	MaxRequestBytes    int64
	MaxResponseBytes   int64         // 0 = unlimited
	MaxRequestDuration time.Duration // 0 = unlimited
	Logger             *slog.Logger
}

// spoofable inbound headers that must never reach the upstream. Forwarded and
// X-Forwarded-* are already removed by ReverseProxy in Rewrite mode.
var strippedRequestHeaders = []string{"X-Real-Ip", "Via", "True-Client-Ip", "Cf-Connecting-Ip"}

var errResponseTooLarge = errors.New("upstream response exceeds limit")

type targetKey struct{}

type handler struct {
	opts  Options
	proxy *httputil.ReverseProxy
	log   *slog.Logger
}

// New returns the relay handler. It expects reqctx.Info in the request context.
func New(opts Options) http.Handler {
	h := &handler{opts: opts, log: opts.Logger}
	if h.log == nil {
		h.log = slog.Default()
	}
	h.proxy = &httputil.ReverseProxy{
		Transport:      opts.Transport,
		Rewrite:        rewrite,
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   h.errorHandler,
		ErrorLog:       slog.NewLogLogger(h.log.Handler(), slog.LevelWarn),
	}
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := reqctx.From(r.Context())
	w.Header().Set(relayerr.HeaderRequestID, info.RequestID)

	vals := r.Header.Values(HeaderTarget)
	switch {
	case len(vals) == 0:
		h.fail(w, info, relayerr.New(relayerr.TargetInvalid))
		return
	case len(vals) > 1:
		h.fail(w, info, relayerr.New(relayerr.RequestInvalid))
		return
	}
	target, perr := h.opts.Policy.Parse(vals[0])
	if perr != nil {
		h.fail(w, info, perr)
		return
	}
	info.TargetHost = target.Hostname()

	if r.ContentLength > h.opts.MaxRequestBytes {
		h.fail(w, info, relayerr.New(relayerr.RequestTooLarge))
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &countingBody{rc: http.MaxBytesReader(w, r.Body, h.opts.MaxRequestBytes), n: &info.BytesIn}
	}

	ctx := context.WithValue(r.Context(), targetKey{}, target)
	if h.opts.MaxRequestDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.opts.MaxRequestDuration)
		defer cancel()
	}
	h.proxy.ServeHTTP(w, r.WithContext(ctx))
}

func (h *handler) fail(w http.ResponseWriter, info *reqctx.Info, e *relayerr.Error) {
	info.ErrorCode = e.Code
	relayerr.Write(w, info.RequestID, e)
}

func rewrite(pr *httputil.ProxyRequest) {
	target := pr.In.Context().Value(targetKey{}).(*url.URL)
	out := *target
	pr.Out.URL = &out
	pr.Out.Host = target.Host
	for k := range pr.Out.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Relay-") {
			delete(pr.Out.Header, k)
		}
	}
	for _, k := range strippedRequestHeaders {
		pr.Out.Header.Del(k)
	}
}

func (h *handler) modifyResponse(resp *http.Response) error {
	for k := range resp.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Relay-") {
			delete(resp.Header, k)
		}
	}
	if max := h.opts.MaxResponseBytes; max > 0 {
		if resp.ContentLength > max {
			return relayerr.New(relayerr.UpstreamProtocolError)
		}
		resp.Body = &limitedBody{rc: resp.Body, remaining: max}
	}
	return nil
}

func (h *handler) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	info := reqctx.From(r.Context())
	e := classify(r, err)
	if e == nil {
		h.log.Debug("client canceled before upstream response", "request_id", info.RequestID)
		return
	}
	h.log.Warn("relay upstream failure", "request_id", info.RequestID, "target_host", info.TargetHost,
		"error_code", string(e.Code), "error", sanitize(err))
	h.fail(w, info, e)
}

// sanitize drops the full URL from *url.Error so query strings never reach logs.
func sanitize(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}

func classify(r *http.Request, err error) *relayerr.Error {
	var re *relayerr.Error
	var mbe *http.MaxBytesError
	var netErr net.Error
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	switch {
	case errors.As(err, &re):
		return re
	case errors.As(err, &mbe):
		return relayerr.New(relayerr.RequestTooLarge)
	case errors.Is(err, transport.ErrDestinationForbidden):
		return relayerr.New(relayerr.TargetForbidden)
	case errors.Is(err, context.Canceled) && r.Context().Err() != nil:
		return nil
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return relayerr.New(relayerr.UpstreamTimeout)
	case errors.As(err, &dnsErr), errors.As(err, &opErr), errors.As(err, &certErr),
		errors.As(err, &hostErr), errors.As(err, &authErr):
		return relayerr.New(relayerr.UpstreamConnectFailed)
	default:
		return relayerr.New(relayerr.UpstreamProtocolError)
	}
}

type countingBody struct {
	rc io.ReadCloser
	n  *int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	atomic.AddInt64(b.n, int64(n))
	return n, err
}

func (b *countingBody) Close() error { return b.rc.Close() }

type limitedBody struct {
	rc        io.ReadCloser
	remaining int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.rc.Read(p)
	if int64(n) > b.remaining {
		n = int(b.remaining)
		b.remaining = 0
		return n, errResponseTooLarge
	}
	b.remaining -= int64(n)
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }
