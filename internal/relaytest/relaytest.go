// Package relaytest provides a TLS upstream and resolver for relay tests.
package relaytest

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/policy"
	"github.com/lllfx/DynamicAPIRelay/internal/transport"
)

// MapResolver resolves names from a fixed map and counts lookups.
type MapResolver struct {
	Hosts map[string][]netip.Addr
	Calls atomic.Int64
}

// LookupNetIP implements transport.Resolver.
func (m *MapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	m.Calls.Add(1)
	if a, ok := m.Hosts[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// Upstream is an httptest TLS server reachable as https://example.com:<port>.
type Upstream struct {
	Server    *httptest.Server
	BaseURL   string
	Port      string
	Transport *http.Transport // trusts the test cert, allows loopback
	Policy    policy.TargetPolicy
	Resolver  *MapResolver
	RootCAs   *x509.CertPool
}

// NewUpstream starts h behind TLS. example.com and evil.test both resolve to
// 127.0.0.1; only example.com is covered by the test certificate.
func NewUpstream(t *testing.T, h http.Handler) *Upstream {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	lo := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	res := &MapResolver{Hosts: map[string][]netip.Addr{"example.com": lo, "evil.test": lo}}
	u := &Upstream{
		Server: srv, BaseURL: "https://example.com:" + port, Port: port,
		Policy: policy.TargetPolicy{AllowedPort: port, MaxLength: 4096}, Resolver: res, RootCAs: pool,
	}
	u.Transport = u.NewTransport(transport.Options{AllowIP: func(netip.Addr) bool { return true }})
	t.Cleanup(u.Transport.CloseIdleConnections)
	return u
}

// NewTransport builds a transport using this upstream's resolver and CA,
// filling unset timeouts with 5s.
func (u *Upstream) NewTransport(o transport.Options) *http.Transport {
	o.Resolver, o.RootCAs = u.Resolver, u.RootCAs
	for _, d := range []*time.Duration{&o.DialTimeout, &o.TLSHandshakeTimeout, &o.ResponseHeaderTimeout, &o.IdleConnTimeout} {
		if *d == 0 {
			*d = 5 * time.Second
		}
	}
	return transport.New(o)
}
