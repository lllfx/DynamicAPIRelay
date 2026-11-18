package stats_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

func wide(now time.Time) stats.Range {
	return stats.Range{From: now.Add(-24 * time.Hour), To: now.Add(time.Minute)}
}

func TestClassification(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	canceled := rec("k", now, 502)
	canceled.ClientCanceled, canceled.ErrorCode = true, "UPSTREAM_CONNECT_FAILED"
	relayErr := rec("k", now, 429)
	relayErr.ErrorCode = "RATE_LIMITED"
	aborted := rec("k", now, 200)
	aborted.Aborted = true
	insert(t, s, canceled, relayErr, aborted, rec("k", now, 401), rec("k", now, 302))
	tot, err := s.KeyTotals(ctx, "k", wide(now))
	if err != nil {
		t.Fatal(err)
	}
	want := stats.Counts{Requests: 5, Success: 1, UpstreamErrors: 1, Aborted: 1, RelayErrors: 1, ClientCanceled: 1}
	if tot.Counts != want {
		t.Fatalf("counts %+v", tot.Counts)
	}
	if rate, ok := tot.ErrorRate(); !ok || rate != 0.75 {
		t.Fatalf("rate %v %v", rate, ok)
	}
	if tot.BytesIn != 50 || tot.BytesOut != 500 || tot.LastSeen.UnixMilli() != now.UnixMilli() {
		t.Errorf("bytes/lastseen %+v", tot)
	}
}

func TestErrorRateZeroDenominator(t *testing.T) {
	if _, ok := (stats.Counts{Requests: 1, ClientCanceled: 1}).ErrorRate(); ok {
		t.Fatal("expected ok=false")
	}
	if _, ok := (stats.Counts{}).ErrorRate(); ok {
		t.Fatal("expected ok=false for empty")
	}
}

func TestKeyTotalsEmpty(t *testing.T) {
	s := openStore(t)
	tot, err := s.KeyTotals(ctx, "nobody", wide(time.Now()))
	if err != nil || tot.Requests != 0 || !tot.LastSeen.IsZero() {
		t.Fatalf("%+v %v", tot, err)
	}
}

func TestSummariesAndHosts(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	h2 := rec("alice", now, 500)
	h2.TargetHost = "b.example.com"
	insert(t, s, rec("alice", now, 200), rec("alice", now, 200), h2, rec("bob", now, 200),
		rec("", now, 401), rec("", now, 401), rec("alice", now.Add(-48*time.Hour), 200))
	sums, err := s.Summaries(ctx, wide(now))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, k := range sums {
		order = append(order, fmt.Sprintf("%s:%d", k.KeyID, k.Requests))
	}
	if fmt.Sprint(order) != "[alice:3 :2 bob:1]" {
		t.Fatalf("order %v", order)
	}
	hosts, err := s.TopHosts(ctx, "alice", wide(now), 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0] != (stats.HostStat{Host: "api.example.com", Requests: 2, Errors: 0, BytesOut: 200}) ||
		hosts[1] != (stats.HostStat{Host: "b.example.com", Requests: 1, Errors: 1, BytesOut: 100}) {
		t.Fatalf("hosts %+v", hosts)
	}
}

func TestErrorBreakdown(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	r1 := rec("k", now, 504)
	r1.ErrorCode = "UPSTREAM_TIMEOUT"
	insert(t, s, r1, r1, rec("k", now, 401), rec("k", now, 200))
	codes, statuses, err := s.ErrorBreakdown(ctx, "k", wide(now))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(codes) != "[{UPSTREAM_TIMEOUT 2}]" || fmt.Sprint(statuses) != "[{401 1}]" {
		t.Fatalf("codes %v statuses %v", codes, statuses)
	}
}

func TestTrendBuckets(t *testing.T) {
	s := openStore(t)
	loc, _ := time.LoadLocation("Asia/Shanghai")
	from := time.Date(2026, 11, 17, 10, 0, 0, 0, loc)
	r := stats.Range{From: from, To: from.Add(24 * time.Hour)}
	insert(t, s, rec("k", from.Add(30*time.Minute), 200), rec("k", from.Add(5*time.Hour+59*time.Minute), 500),
		rec("j", from.Add(5*time.Hour), 200))
	b, err := s.Trend(ctx, nil, r, time.Hour, loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 24 || !b[0].Start.Equal(from) || !b[23].Start.Equal(from.Add(23*time.Hour)) {
		t.Fatalf("len=%d first=%v", len(b), b[0].Start)
	}
	if b[0].Success != 1 || b[5].UpstreamErrors != 1 || b[5].Success != 1 || b[1].Requests != 0 {
		t.Fatalf("bucket counts %+v %+v", b[0], b[5])
	}
	key := "k"
	b, _ = s.Trend(ctx, &key, r, time.Hour, loc)
	if b[5].Success != 0 || b[5].UpstreamErrors != 1 {
		t.Fatalf("key filter ignored %+v", b[5])
	}
	day := time.Date(2026, 11, 11, 0, 0, 0, 0, loc)
	b, _ = s.Trend(ctx, nil, stats.Range{From: day, To: day.Add(7 * 24 * time.Hour)}, 24*time.Hour, loc)
	if len(b) != 7 || !b[0].Start.Equal(day) || b[6].Requests != 3 {
		t.Fatalf("daily len=%d first=%v last=%+v", len(b), b[0].Start, b[6])
	}
}

func TestRecentFailuresPaging(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	var recs []stats.Record
	for i := 0; i < 60; i++ {
		recs = append(recs, rec("k", now, 500))
	}
	for i := 0; i < 10; i++ {
		recs = append(recs, rec("k", now, 200))
	}
	for i := 0; i < 5; i++ {
		c := rec("k", now, 200)
		c.ClientCanceled = true
		recs = append(recs, c)
	}
	insert(t, s, recs...)
	p1, err := s.RecentFailures(ctx, "k", wide(now), 0, 50)
	if err != nil || len(p1) != 50 {
		t.Fatalf("page1 %d %v", len(p1), err)
	}
	for i := 1; i < len(p1); i++ {
		if p1[i].ID >= p1[i-1].ID || p1[i].Status != 500 {
			t.Fatalf("bad order or row %+v", p1[i])
		}
	}
	p2, _ := s.RecentFailures(ctx, "k", wide(now), p1[49].ID, 50)
	if len(p2) != 10 {
		t.Fatalf("page2 %d", len(p2))
	}
	if p1[0].RequestID != "req_x" || p1[0].ClientIP != "203.0.113.9" || p1[0].Duration != 5*time.Millisecond {
		t.Errorf("fields %+v", p1[0])
	}
}

func TestP95(t *testing.T) {
	s := openStore(t)
	now := time.Now()
	var recs []stats.Record
	for i := 1; i <= 100; i++ {
		r := rec("k", now, 200)
		r.Duration = time.Duration(i) * time.Millisecond
		recs = append(recs, r)
	}
	insert(t, s, recs...)
	tot, _ := s.KeyTotals(ctx, "k", wide(now))
	if tot.P95 != 95*time.Millisecond {
		t.Fatalf("p95 %v", tot.P95)
	}
	sums, _ := s.Summaries(ctx, wide(now))
	if sums[0].P95 != 95*time.Millisecond {
		t.Fatalf("summary p95 %v", sums[0].P95)
	}
}
