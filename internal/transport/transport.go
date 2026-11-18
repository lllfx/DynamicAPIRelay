// Package transport builds the shared outbound http.Transport that enforces
// destination IP policy at connection time.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/netguard"
)

// Resolver resolves hostnames; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configures New.
type Options struct {
	Resolver              Resolver              // nil → net.DefaultResolver
	AllowIP               func(netip.Addr) bool // nil → netguard.IsPublic
	RootCAs               *x509.CertPool        // nil → system roots; tests only
	DialTimeout           time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
}

// ErrDestinationForbidden is returned when no permitted address is available.
var ErrDestinationForbidden = errors.New("destination address not allowed")

// New returns a hardened transport: no proxy env, no transparent
// decompression, TLS >= 1.2 with hostname verification, and dial-time IP checks.
func New(opts Options) *http.Transport {
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	allow := opts.AllowIP
	if allow == nil {
		allow = netguard.IsPublic
	}
	dialer := &net.Dialer{
		Timeout: opts.DialTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !allow(ap.Addr()) {
				return ErrDestinationForbidden
			}
			return nil
		},
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var addrs []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			addrs = []netip.Addr{ip}
		} else {
			addrs, err = opts.Resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
		}
		permitted := allowedAddrs(addrs, allow)
		if len(permitted) == 0 {
			return nil, fmt.Errorf("dial %s: %w", host, ErrDestinationForbidden)
		}
		var lastErr error
		for _, ip := range permitted {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs},
		TLSHandshakeTimeout:   opts.TLSHandshakeTimeout,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		IdleConnTimeout:       opts.IdleConnTimeout,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   16,
	}
}

func allowedAddrs(addrs []netip.Addr, allow func(netip.Addr) bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if allow(a) {
			out = append(out, a)
		}
	}
	return out
}
