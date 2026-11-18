package stats_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

var ctx = context.Background()

func openStore(t *testing.T) *stats.Store {
	t.Helper()
	s, err := stats.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func rec(key string, ts time.Time, status int) stats.Record {
	return stats.Record{Time: ts, RequestID: "req_x", KeyID: key, ClientIP: "203.0.113.9", Method: "GET",
		TargetHost: "api.example.com", Status: status, BytesIn: 10, BytesOut: 100, Duration: 5 * time.Millisecond}
}

func insert(t *testing.T, s *stats.Store, recs ...stats.Record) {
	t.Helper()
	if err := s.Insert(ctx, recs); err != nil {
		t.Fatal(err)
	}
}
