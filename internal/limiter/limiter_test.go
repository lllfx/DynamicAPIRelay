package limiter_test

import (
	"testing"

	"github.com/lllfx/DynamicAPIRelay/internal/limiter"
	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
)

func TestConcurrencyLimit(t *testing.T) {
	l := limiter.New(1000, 1000, 2)
	r1, e1 := l.Acquire("a")
	r2, e2 := l.Acquire("a")
	if e1 != nil || e2 != nil {
		t.Fatalf("unexpected %v %v", e1, e2)
	}
	if _, e3 := l.Acquire("a"); e3 == nil || e3.Code != relayerr.ConcurrencyLimited {
		t.Fatalf("want ConcurrencyLimited, got %v", e3)
	}
	if _, e4 := l.Acquire("b"); e4 != nil {
		t.Fatalf("keys must be isolated: %v", e4)
	}
	r1()
	r1() // idempotent: must not free a second slot
	if _, e5 := l.Acquire("a"); e5 != nil {
		t.Fatalf("slot not released: %v", e5)
	}
	if _, e6 := l.Acquire("a"); e6 == nil {
		t.Fatal("double release freed an extra slot")
	}
	r2()
}

func TestRateLimit(t *testing.T) {
	l := limiter.New(1, 2, 100)
	for i := 0; i < 2; i++ {
		if _, err := l.Acquire("a"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if _, err := l.Acquire("a"); err == nil || err.Code != relayerr.RateLimited {
		t.Fatalf("want RateLimited, got %v", err)
	}
}
