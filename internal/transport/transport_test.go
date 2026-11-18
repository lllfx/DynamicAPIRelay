package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/netguard"
)

type mapResolver map[string][]string

func (m mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range m[host] {
		out = append(out, netip.MustParseAddr(s))
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

func TestAllowedAddrsFiltersMixed(t *testing.T) {
	in := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::1")}
	got := allowedAddrs(in, netguard.IsPublic)
	if !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("8.8.8.8")}) {
		t.Errorf("got %v", got)
	}
}

func TestDialRejectsPrivateResolution(t *testing.T) {
	tr := New(Options{Resolver: mapResolver{"evil.example": {"127.0.0.1", "10.0.0.1"}}, DialTimeout: time.Second})
	_, err := tr.DialContext(context.Background(), "tcp", "evil.example:443")
	if !errors.Is(err, ErrDestinationForbidden) {
		t.Fatalf("got %v", err)
	}
}

func TestDialControlRejectsLiteralPrivate(t *testing.T) {
	tr := New(Options{DialTimeout: time.Second})
	_, err := tr.DialContext(context.Background(), "tcp", "127.0.0.1:443")
	if !errors.Is(err, ErrDestinationForbidden) {
		t.Fatalf("got %v", err)
	}
}

func TestDialResolverErrorNotForbidden(t *testing.T) {
	tr := New(Options{Resolver: mapResolver{}, DialTimeout: time.Second})
	_, err := tr.DialContext(context.Background(), "tcp", "nx.example:443")
	if err == nil || errors.Is(err, ErrDestinationForbidden) {
		t.Fatalf("got %v", err)
	}
}

func TestTransportHardening(t *testing.T) {
	tr := New(Options{DialTimeout: time.Second, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second, IdleConnTimeout: 4 * time.Second})
	if tr.Proxy != nil || !tr.DisableCompression || tr.TLSClientConfig == nil ||
		tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("transport not hardened: %+v", tr)
	}
	if tr.TLSHandshakeTimeout != 2*time.Second || tr.ResponseHeaderTimeout != 3*time.Second || tr.IdleConnTimeout != 4*time.Second {
		t.Errorf("timeouts not applied")
	}
}
