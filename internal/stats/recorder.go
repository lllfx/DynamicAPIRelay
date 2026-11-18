package stats

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Sink persists batches of records; *Store satisfies it.
type Sink interface {
	Insert(ctx context.Context, recs []Record) error
}

// RecorderOptions tunes batching. Production: 10000, 200, 1s.
type RecorderOptions struct {
	QueueSize     int
	BatchSize     int
	FlushInterval time.Duration
}

// Recorder queues records without blocking and writes them in batches.
type Recorder struct {
	sink    Sink
	log     *slog.Logger
	opts    RecorderOptions
	ch      chan Record
	done    chan struct{}
	dropped atomic.Int64
	mu      sync.RWMutex
	closed  bool
}

// NewRecorder starts the background writer.
func NewRecorder(sink Sink, logger *slog.Logger, opts RecorderOptions) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Recorder{sink: sink, log: logger, opts: opts, ch: make(chan Record, opts.QueueSize), done: make(chan struct{})}
	go r.loop()
	return r
}

// Record enqueues rec, dropping it if the queue is full or the recorder is closed.
func (r *Recorder) Record(rec Record) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		r.dropped.Add(1)
		return
	}
	select {
	case r.ch <- rec:
	default:
		r.dropped.Add(1)
	}
}

// Dropped returns how many records were discarded since start.
func (r *Recorder) Dropped() int64 { return r.dropped.Load() }

// Close stops accepting records and waits for the queue to be flushed.
func (r *Recorder) Close(ctx context.Context) error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.ch)
	}
	r.mu.Unlock()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Recorder) loop() {
	defer close(r.done)
	ticker := time.NewTicker(r.opts.FlushInterval)
	defer ticker.Stop()
	batch := make([]Record, 0, r.opts.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := r.sink.Insert(ctx, batch); err != nil {
			r.log.Error("stats insert failed; batch dropped", "count", len(batch), "error", err)
			r.dropped.Add(int64(len(batch)))
		}
		cancel()
		batch = make([]Record, 0, r.opts.BatchSize)
	}
	for {
		select {
		case rec, ok := <-r.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, rec)
			if len(batch) >= r.opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
