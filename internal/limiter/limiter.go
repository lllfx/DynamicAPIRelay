// Package limiter enforces per-key request rate and in-flight concurrency.
package limiter

import (
	"sync"

	"golang.org/x/time/rate"

	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
)

type bucket struct {
	rate *rate.Limiter
	sem  chan struct{}
}

// Limiter holds lazily created per-key limits.
type Limiter struct {
	mu            sync.Mutex
	keys          map[string]*bucket
	ratePerSec    float64
	burst         int
	maxConcurrent int
}

// New creates a limiter applying the same limits to every key.
func New(ratePerSec float64, burst, maxConcurrent int) *Limiter {
	return &Limiter{keys: map[string]*bucket{}, ratePerSec: ratePerSec, burst: burst, maxConcurrent: maxConcurrent}
}

func (l *Limiter) get(keyID string) *bucket {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.keys[keyID]
	if !ok {
		b = &bucket{rate: rate.NewLimiter(rate.Limit(l.ratePerSec), l.burst), sem: make(chan struct{}, l.maxConcurrent)}
		l.keys[keyID] = b
	}
	return b
}

// Acquire admits one request for keyID. On success the caller must call
// release (idempotent) when the request finishes.
func (l *Limiter) Acquire(keyID string) (release func(), err *relayerr.Error) {
	b := l.get(keyID)
	if !b.rate.Allow() {
		return nil, relayerr.New(relayerr.RateLimited)
	}
	select {
	case b.sem <- struct{}{}:
	default:
		return nil, relayerr.New(relayerr.ConcurrencyLimited)
	}
	var once sync.Once
	return func() { once.Do(func() { <-b.sem }) }, nil
}
