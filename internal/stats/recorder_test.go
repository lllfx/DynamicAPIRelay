package stats_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

type fakeSink struct {
	mu      sync.Mutex
	batches [][]stats.Record
	fail    int           // number of initial calls that fail
	block   chan struct{} // if non-nil, Insert blocks until closed
}

func (f *fakeSink) Insert(_ context.Context, recs []stats.Record) error {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail > 0 {
		f.fail--
		return errors.New("disk on fire")
	}
	f.batches = append(f.batches, append([]stats.Record(nil), recs...))
	return nil
}

func (f *fakeSink) total() (batches, recs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.batches {
		recs += len(b)
	}
	return len(f.batches), recs
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRecorderFlushesBatch(t *testing.T) {
	sink := &fakeSink{}
	r := stats.NewRecorder(sink, nil, stats.RecorderOptions{QueueSize: 10, BatchSize: 2, FlushInterval: time.Hour})
	defer r.Close(context.Background())
	r.Record(rec("a", time.Now(), 200))
	r.Record(rec("a", time.Now(), 200))
	waitFor(t, func() bool { b, n := sink.total(); return b == 1 && n == 2 })
}

func TestRecorderFlushesOnInterval(t *testing.T) {
	sink := &fakeSink{}
	r := stats.NewRecorder(sink, nil, stats.RecorderOptions{QueueSize: 10, BatchSize: 100, FlushInterval: 50 * time.Millisecond})
	defer r.Close(context.Background())
	r.Record(rec("a", time.Now(), 200))
	waitFor(t, func() bool { _, n := sink.total(); return n == 1 })
}

func TestRecorderCloseFlushes(t *testing.T) {
	sink := &fakeSink{}
	r := stats.NewRecorder(sink, nil, stats.RecorderOptions{QueueSize: 10, BatchSize: 100, FlushInterval: time.Hour})
	for i := 0; i < 5; i++ {
		r.Record(rec("a", time.Now(), 200))
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, n := sink.total(); n != 5 {
		t.Fatalf("flushed %d", n)
	}
	r.Record(rec("a", time.Now(), 200)) // after Close: must not panic
}

func TestRecordNeverBlocks(t *testing.T) {
	sink := &fakeSink{block: make(chan struct{})}
	defer close(sink.block)
	r := stats.NewRecorder(sink, nil, stats.RecorderOptions{QueueSize: 2, BatchSize: 1, FlushInterval: time.Hour})
	start := time.Now()
	for i := 0; i < 100; i++ {
		r.Record(rec("a", time.Now(), 200))
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("Record blocked for %v", d)
	}
	if r.Dropped() == 0 {
		t.Fatal("expected dropped records")
	}
}

func TestInsertFailureKeepsRunning(t *testing.T) {
	sink := &fakeSink{fail: 1}
	r := stats.NewRecorder(sink, nil, stats.RecorderOptions{QueueSize: 10, BatchSize: 1, FlushInterval: time.Hour})
	defer r.Close(context.Background())
	r.Record(rec("a", time.Now(), 200))
	time.Sleep(50 * time.Millisecond)
	r.Record(rec("b", time.Now(), 200))
	waitFor(t, func() bool { _, n := sink.total(); return n == 1 })
}
