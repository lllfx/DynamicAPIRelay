// Package policy validates X-Relay-Target URLs before any network access.
package policy

import (
	"net/netip"
	"net/url"
	"strings"

	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
)

// TargetPolicy holds parse-time target restrictions.
type TargetPolicy struct {
	AllowedPort string // "443" in production; tests may inject another port
	MaxLength   int    // maximum raw target length in bytes
}

// Default returns the production policy: HTTPS on 443, 4 KiB max target.
func Default() TargetPolicy { return TargetPolicy{AllowedPort: "443", MaxLength: 4096} }

// Parse validates raw and returns the outbound URL. RawPath and RawQuery are
// preserved byte-for-byte so upstream signatures stay valid.
func (p TargetPolicy) Parse(raw string) (*url.URL, *relayerr.Error) {
	invalid := relayerr.New(relayerr.TargetInvalid)
	forbidden := relayerr.New(relayerr.TargetForbidden)

	if raw == "" || len(raw) > p.MaxLength || strings.ContainsRune(raw, '#') ||
		hasForbiddenBytes(raw) || !validPercentEncoding(raw) {
		return nil, invalid
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.User != nil {
		return nil, invalid
	}
	if u.Scheme != "https" {
		return nil, forbidden
	}
	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		return nil, forbidden
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, forbidden
	}
	host = strings.ToLower(host)
	if !validLDH(host) {
		return nil, invalid
	}
	labels := strings.Split(host, ".")
	last := labels[len(labels)-1]
	if len(labels) < 2 || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		allDigits(last) || strings.HasPrefix(last, "0x") {
		return nil, forbidden
	}
	if !pathRoundTrips(raw, u) {
		return nil, invalid
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return nil, forbidden // empty port after ':' is ambiguous
	}
	effective := port
	if effective == "" {
		effective = "443"
	}
	if effective != p.AllowedPort {
		return nil, forbidden
	}

	out := *u
	if port == "" {
		out.Host = host
	} else {
		out.Host = host + ":" + port
	}
	if out.Path == "" {
		out.Path = "/"
		out.RawPath = ""
	}
	return &out, nil
}

// pathRoundTrips reports whether Go will send the path exactly as written.
// When the raw path holds percent-escapes but also characters Go re-escapes
// (e.g. "{}|^"), Go drops RawPath and re-encodes the decoded path, which can
// turn %2F into a real '/'. Such targets are rejected rather than altered.
// Paths without '%' may be re-escaped harmlessly and are allowed.
func pathRoundTrips(raw string, u *url.URL) bool {
	rest := raw[len(u.Scheme)+len("://"):]
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[i:]
	} else {
		rest = ""
	}
	rawPath, _, _ := strings.Cut(rest, "?")
	return !strings.Contains(rawPath, "%") || u.EscapedPath() == rawPath
}

func hasForbiddenBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func validPercentEncoding(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		}
	}
	return true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// validLDH reports whether host is ASCII letters/digits/hyphens in dot-separated
// labels of 1-63 bytes, not starting or ending with '-', total <= 253 bytes.
// A trailing dot yields an empty label and is rejected.
func validLDH(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
