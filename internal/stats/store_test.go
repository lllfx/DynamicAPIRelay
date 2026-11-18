package stats_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

func TestOpenCreatesSchema(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	path := filepath.Join(dir, "s.db")
	s, err := stats.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm %v err %v", fi.Mode().Perm(), err)
	}
	db, _ := sql.Open("sqlite", path)
	defer db.Close()
	var mode string
	var ver int
	db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	db.QueryRow("PRAGMA user_version").Scan(&ver)
	if mode != "wal" || ver != 1 {
		t.Errorf("journal_mode=%q user_version=%d", mode, ver)
	}
	s2, err := stats.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s2.Close()
}

func TestInsertAndPurge(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	insert(t, s, rec("a", now.Add(-40*24*time.Hour), 200), rec("a", now.Add(-31*24*time.Hour), 200), rec("a", now.Add(-24*time.Hour), 200))
	n, err := s.Purge(ctx, now.Add(-30*24*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("purged %d err %v", n, err)
	}
	tot, err := s.KeyTotals(ctx, "a", stats.Range{From: now.Add(-365 * 24 * time.Hour), To: now.Add(time.Hour)})
	if err != nil || tot.Requests != 1 {
		t.Fatalf("remaining %d err %v", tot.Requests, err)
	}
}

func TestRunRetentionPurgesImmediately(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	insert(t, s, rec("a", now.Add(-40*24*time.Hour), 200), rec("a", now, 200))
	c, cancel := contextWithCancel()
	done := make(chan struct{})
	go func() { stats.RunRetention(c, s, 30*24*time.Hour, time.Hour, time.Now, nil); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		tot, _ := s.KeyTotals(ctx, "a", stats.Range{From: now.Add(-365 * 24 * time.Hour), To: now.Add(time.Hour)})
		if tot.Requests == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retention did not purge")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
