// Package config loads relay settings from environment variables.
package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config holds all relay runtime settings. The target port is fixed at 443
// and intentionally not configurable.
type Config struct {
	ListenAddr            string            // RELAY_LISTEN_ADDR
	Keys                  map[string]string // RELAY_KEYS: keyID -> secret
	MaxRequestBytes       int64             // RELAY_MAX_REQUEST_BYTES
	MaxResponseBytes      int64             // RELAY_MAX_RESPONSE_BYTES (0 = unlimited)
	RatePerSec            float64           // RELAY_RATE_PER_SEC
	RateBurst             int               // RELAY_RATE_BURST
	MaxConcurrent         int               // RELAY_MAX_CONCURRENT
	DialTimeout           time.Duration     // RELAY_DIAL_TIMEOUT
	TLSHandshakeTimeout   time.Duration     // RELAY_TLS_HANDSHAKE_TIMEOUT
	ResponseHeaderTimeout time.Duration     // RELAY_RESPONSE_HEADER_TIMEOUT
	IdleConnTimeout       time.Duration     // RELAY_IDLE_CONN_TIMEOUT
	MaxRequestDuration    time.Duration     // RELAY_MAX_REQUEST_DURATION (0 = unlimited)
	ReadHeaderTimeout     time.Duration     // RELAY_READ_HEADER_TIMEOUT
}

// MinKeyBytes is the minimum relay secret length.
const MinKeyBytes = 32

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Load reads configuration through lookup (os.LookupEnv in production).
func Load(lookup func(string) (string, bool)) (Config, error) {
	c := Config{ListenAddr: "127.0.0.1:8080"}
	if v, ok := lookup("RELAY_LISTEN_ADDR"); ok && v != "" {
		c.ListenAddr = v
	}
	keys, err := parseKeys(lookup)
	if err != nil {
		return Config{}, err
	}
	c.Keys = keys

	var errs []error
	c.MaxRequestBytes = getInt(lookup, "RELAY_MAX_REQUEST_BYTES", 104857600, 1, &errs)
	c.MaxResponseBytes = getInt(lookup, "RELAY_MAX_RESPONSE_BYTES", 0, 0, &errs)
	c.RatePerSec = getFloat(lookup, "RELAY_RATE_PER_SEC", 30, &errs)
	c.RateBurst = int(getInt(lookup, "RELAY_RATE_BURST", 30, 1, &errs))
	c.MaxConcurrent = int(getInt(lookup, "RELAY_MAX_CONCURRENT", 20, 1, &errs))
	c.DialTimeout = getDur(lookup, "RELAY_DIAL_TIMEOUT", 10*time.Second, &errs)
	c.TLSHandshakeTimeout = getDur(lookup, "RELAY_TLS_HANDSHAKE_TIMEOUT", 10*time.Second, &errs)
	c.ResponseHeaderTimeout = getDur(lookup, "RELAY_RESPONSE_HEADER_TIMEOUT", 60*time.Second, &errs)
	c.IdleConnTimeout = getDur(lookup, "RELAY_IDLE_CONN_TIMEOUT", 90*time.Second, &errs)
	c.MaxRequestDuration = getDur(lookup, "RELAY_MAX_REQUEST_DURATION", 0, &errs)
	c.ReadHeaderTimeout = getDur(lookup, "RELAY_READ_HEADER_TIMEOUT", 10*time.Second, &errs)
	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return c, nil
}

func parseKeys(lookup func(string) (string, bool)) (map[string]string, error) {
	raw, _ := lookup("RELAY_KEYS")
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("RELAY_KEYS is required (format id:secret[,id:secret...])")
	}
	keys := map[string]string{}
	seen := map[string]bool{}
	for i, entry := range strings.Split(raw, ",") {
		id, secret, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok {
			return nil, fmt.Errorf("RELAY_KEYS entry %d: missing ':' separator", i+1)
		}
		if !keyIDPattern.MatchString(id) {
			return nil, fmt.Errorf("RELAY_KEYS entry %d: key id must match %s", i+1, keyIDPattern)
		}
		if len(secret) < MinKeyBytes {
			return nil, fmt.Errorf("RELAY_KEYS key %q: secret must be at least %d bytes", id, MinKeyBytes)
		}
		if _, dup := keys[id]; dup {
			return nil, fmt.Errorf("RELAY_KEYS key %q: duplicate key id", id)
		}
		if seen[secret] {
			return nil, fmt.Errorf("RELAY_KEYS key %q: secret reused by another key", id)
		}
		keys[id], seen[secret] = secret, true
	}
	return keys, nil
}

func getInt(lookup func(string) (string, bool), name string, def, min int64, errs *[]error) int64 {
	v, ok := lookup(name)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < min {
		*errs = append(*errs, fmt.Errorf("%s: must be an integer >= %d", name, min))
		return def
	}
	return n
}

func getFloat(lookup func(string) (string, bool), name string, def float64, errs *[]error) float64 {
	v, ok := lookup(name)
	if !ok || v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || !(f > 0) {
		*errs = append(*errs, fmt.Errorf("%s: must be a number > 0", name))
		return def
	}
	return f
}

func getDur(lookup func(string) (string, bool), name string, def time.Duration, errs *[]error) time.Duration {
	v, ok := lookup(name)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		*errs = append(*errs, fmt.Errorf("%s: must be a non-negative duration like 10s", name))
		return def
	}
	return d
}
