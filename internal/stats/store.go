// Package stats persists per-request relay records in SQLite and answers
// dashboard queries. Records never contain headers, URL paths/queries or bodies.
package stats

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Record is one finished /v1/relay request.
type Record struct {
	Time                                           time.Time // request start
	RequestID, KeyID, ClientIP, Method, TargetHost string
	Status                                         int
	ErrorCode                                      string
	Aborted, ClientCanceled                        bool
	BytesIn, BytesOut                              int64
	Duration                                       time.Duration
}

const schemaVersion = 1

const schema = `
CREATE TABLE IF NOT EXISTS requests (
  id              INTEGER PRIMARY KEY,
  ts              INTEGER NOT NULL,
  request_id      TEXT    NOT NULL,
  key_id          TEXT    NOT NULL,
  client_ip       TEXT    NOT NULL,
  method          TEXT    NOT NULL,
  target_host     TEXT    NOT NULL,
  status          INTEGER NOT NULL,
  error_code      TEXT    NOT NULL,
  aborted         INTEGER NOT NULL,
  client_canceled INTEGER NOT NULL,
  bytes_in        INTEGER NOT NULL,
  bytes_out       INTEGER NOT NULL,
  duration_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_ts     ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_key_ts ON requests(key_id, ts);
`

// Store wraps a single-writer connection and a separate read pool.
type Store struct {
	w, r *sql.DB
}

// Open creates (if needed) and opens the database at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("stats: create dir: %w", err)
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	if err := migrate(w); err != nil {
		w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn)
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(4)
	return &Store{w: w, r: r}, nil
}

func migrate(db *sql.DB) error {
	var ver int
	if err := db.QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		return fmt.Errorf("stats: read schema version: %w", err)
	}
	if ver > schemaVersion {
		return fmt.Errorf("stats: database schema version %d is newer than supported %d", ver, schemaVersion)
	}
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("stats: create schema: %w", err)
	}
	_, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
	return err
}

// Close closes both pools.
func (s *Store) Close() error {
	err1 := s.r.Close()
	err2 := s.w.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Insert writes recs in one transaction.
func (s *Store) Insert(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO requests
		(ts, request_id, key_id, client_ip, method, target_host, status, error_code, aborted, client_canceled, bytes_in, bytes_out, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range recs {
		if _, err := stmt.ExecContext(ctx, r.Time.UnixMilli(), r.RequestID, r.KeyID, r.ClientIP, r.Method, r.TargetHost,
			r.Status, r.ErrorCode, b2i(r.Aborted), b2i(r.ClientCanceled), r.BytesIn, r.BytesOut, r.Duration.Milliseconds()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Purge deletes records older than before in batches of 5000 rows.
func (s *Store) Purge(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	for {
		res, err := s.w.ExecContext(ctx,
			`DELETE FROM requests WHERE id IN (SELECT id FROM requests WHERE ts < ? LIMIT 5000)`, before.UnixMilli())
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n == 0 {
			return total, nil
		}
	}
}

// RunRetention purges records older than retention immediately and then
// every interval until ctx is done.
func RunRetention(ctx context.Context, s *Store, retention, every time.Duration, now func() time.Time, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	purge := func() {
		n, err := s.Purge(ctx, now().Add(-retention))
		if err != nil && ctx.Err() == nil {
			logger.Error("stats retention purge failed", "error", err)
		} else if n > 0 {
			logger.Info("stats retention purged records", "count", n)
		}
	}
	purge()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			purge()
		}
	}
}
