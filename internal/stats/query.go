package stats

import (
	"context"
	"database/sql"
	"strconv"
	"time"
)

// categorySQL classifies a row; priority: canceled > relay > aborted > upstream > success.
const categorySQL = `CASE WHEN client_canceled=1 THEN 'canceled' WHEN error_code<>'' THEN 'relay'
     WHEN aborted=1 THEN 'aborted' WHEN status>=400 THEN 'upstream' ELSE 'success' END`

const countsSQL = `COUNT(*), TOTAL(cat='success'), TOTAL(cat='upstream'), TOTAL(cat='aborted'),
	TOTAL(cat='relay'), TOTAL(cat='canceled')`

// Range is the half-open interval [From, To).
type Range struct{ From, To time.Time }

// Counts are per-category request counts.
type Counts struct{ Requests, Success, UpstreamErrors, Aborted, RelayErrors, ClientCanceled int64 }

// ErrorRate is (relay + aborted + upstream) / (requests - canceled); ok is false
// when the denominator is zero.
func (c Counts) ErrorRate() (rate float64, ok bool) {
	den := c.Requests - c.ClientCanceled
	if den <= 0 {
		return 0, false
	}
	return float64(c.RelayErrors+c.Aborted+c.UpstreamErrors) / float64(den), true
}

// Totals aggregate one key (or everything) over a range.
type Totals struct {
	Counts
	BytesIn, BytesOut int64
	P95               time.Duration
	LastSeen          time.Time
}

// KeySummary is one row of the overview table.
type KeySummary struct {
	KeyID string
	Totals
}

// Bucket is one trend interval starting at Start.
type Bucket struct {
	Start time.Time
	Counts
}

// HostStat summarizes one target host.
type HostStat struct {
	Host                       string
	Requests, Errors, BytesOut int64
}

// LabelCount is a generic label/count pair.
type LabelCount struct {
	Label string
	Count int64
}

// Failure is one non-success, non-canceled request.
type Failure struct {
	ID                 int64
	Time               time.Time
	Method, TargetHost string
	Status             int
	ErrorCode          string
	Aborted            bool
	Duration           time.Duration
	RequestID          string
	ClientIP           string
}

func ms(t time.Time) int64 { return t.UnixMilli() }

// scoped returns a subquery selecting rows (with cat) for the range and optional key.
func scoped(keyID *string, r Range) (string, []any) {
	q := `SELECT *, ` + categorySQL + ` AS cat FROM requests WHERE ts >= ? AND ts < ?`
	args := []any{ms(r.From), ms(r.To)}
	if keyID != nil {
		q += ` AND key_id = ?`
		args = append(args, *keyID)
	}
	return "(" + q + ")", args
}

// countFloats receives TOTAL() results, which SQLite returns as REAL.
type countFloats [5]float64

// countDest returns scan destinations matching countsSQL.
func countDest(c *Counts, cf *countFloats) []any {
	return []any{&c.Requests, &cf[0], &cf[1], &cf[2], &cf[3], &cf[4]}
}

func (cf *countFloats) apply(c *Counts) {
	c.Success, c.UpstreamErrors, c.Aborted, c.RelayErrors, c.ClientCanceled =
		int64(cf[0]), int64(cf[1]), int64(cf[2]), int64(cf[3]), int64(cf[4])
}

// Summaries returns totals for every key with data in r, by request count desc.
func (s *Store) Summaries(ctx context.Context, r Range) ([]KeySummary, error) {
	sub, args := scoped(nil, r)
	rows, err := s.r.QueryContext(ctx, `SELECT key_id, `+countsSQL+`, TOTAL(bytes_in), TOTAL(bytes_out), MAX(ts)
		FROM `+sub+` GROUP BY key_id ORDER BY COUNT(*) DESC, key_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeySummary
	for rows.Next() {
		var ks KeySummary
		var cf countFloats
		var bin, bout float64
		var last int64
		dest := append([]any{&ks.KeyID}, countDest(&ks.Counts, &cf)...)
		if err := rows.Scan(append(dest, &bin, &bout, &last)...); err != nil {
			return nil, err
		}
		cf.apply(&ks.Counts)
		ks.BytesIn, ks.BytesOut, ks.LastSeen = int64(bin), int64(bout), time.UnixMilli(last)
		out = append(out, ks)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		key := out[i].KeyID
		if out[i].P95, err = s.p95(ctx, &key, r, out[i].Requests); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// KeyTotals returns totals for one key; zero values if it has no data.
func (s *Store) KeyTotals(ctx context.Context, keyID string, r Range) (Totals, error) {
	sub, args := scoped(&keyID, r)
	var t Totals
	var cf countFloats
	var bin, bout float64
	var last sql.NullInt64
	dest := append(countDest(&t.Counts, &cf), &bin, &bout, &last)
	if err := s.r.QueryRowContext(ctx, `SELECT `+countsSQL+`, TOTAL(bytes_in), TOTAL(bytes_out), MAX(ts) FROM `+sub, args...).
		Scan(dest...); err != nil {
		return Totals{}, err
	}
	cf.apply(&t.Counts)
	t.BytesIn, t.BytesOut = int64(bin), int64(bout)
	if last.Valid {
		t.LastSeen = time.UnixMilli(last.Int64)
	}
	var err error
	t.P95, err = s.p95(ctx, &keyID, r, t.Requests)
	return t, err
}

func (s *Store) p95(ctx context.Context, keyID *string, r Range, n int64) (time.Duration, error) {
	if n == 0 {
		return 0, nil
	}
	offset := (n*95+99)/100 - 1
	sub, args := scoped(keyID, r)
	var d int64
	err := s.r.QueryRowContext(ctx, `SELECT duration_ms FROM `+sub+` ORDER BY duration_ms LIMIT 1 OFFSET ?`,
		append(args, offset)...).Scan(&d)
	return time.Duration(d) * time.Millisecond, err
}

// Trend returns contiguous buckets of width step covering r, aligned in loc.
// keyID nil means all keys.
func (s *Store) Trend(ctx context.Context, keyID *string, r Range, step time.Duration, loc *time.Location) ([]Bucket, error) {
	_, off := r.From.In(loc).Zone()
	offMs, stepMs := int64(off)*1000, step.Milliseconds()
	align := func(t int64) int64 { return ((t+offMs)/stepMs)*stepMs - offMs }
	start := align(ms(r.From))
	var buckets []Bucket
	for t := start; t < ms(r.To); t += stepMs {
		buckets = append(buckets, Bucket{Start: time.UnixMilli(t).In(loc)})
	}
	sub, args := scoped(keyID, r)
	rows, err := s.r.QueryContext(ctx, `SELECT ((ts + ?) / ?) * ? - ? AS b, `+countsSQL+` FROM `+sub+` GROUP BY b`,
		append([]any{offMs, stepMs, stepMs, offMs}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b int64
		var c Counts
		var cf countFloats
		if err := rows.Scan(append([]any{&b}, countDest(&c, &cf)...)...); err != nil {
			return nil, err
		}
		cf.apply(&c)
		if i := (b - start) / stepMs; i >= 0 && int(i) < len(buckets) {
			buckets[i].Counts = c
		}
	}
	return buckets, rows.Err()
}

// TopHosts returns up to limit target hosts for keyID by request count desc.
func (s *Store) TopHosts(ctx context.Context, keyID string, r Range, limit int) ([]HostStat, error) {
	sub, args := scoped(&keyID, r)
	rows, err := s.r.QueryContext(ctx, `SELECT target_host, COUNT(*), TOTAL(cat IN ('relay','aborted','upstream')), TOTAL(bytes_out)
		FROM `+sub+` GROUP BY target_host ORDER BY COUNT(*) DESC, target_host LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostStat
	for rows.Next() {
		var h HostStat
		var errs, bout float64
		if err := rows.Scan(&h.Host, &h.Requests, &errs, &bout); err != nil {
			return nil, err
		}
		h.Errors, h.BytesOut = int64(errs), int64(bout)
		out = append(out, h)
	}
	return out, rows.Err()
}

// ErrorBreakdown counts relay errors by code and upstream errors by status.
func (s *Store) ErrorBreakdown(ctx context.Context, keyID string, r Range) (codes, statuses []LabelCount, err error) {
	sub, args := scoped(&keyID, r)
	if codes, err = s.labelCounts(ctx, `SELECT error_code, COUNT(*) FROM `+sub+` WHERE cat='relay'
		GROUP BY error_code ORDER BY COUNT(*) DESC, error_code`, args); err != nil {
		return nil, nil, err
	}
	statuses, err = s.labelCounts(ctx, `SELECT status, COUNT(*) FROM `+sub+` WHERE cat='upstream'
		GROUP BY status ORDER BY COUNT(*) DESC, status`, args)
	return codes, statuses, err
}

func (s *Store) labelCounts(ctx context.Context, q string, args []any) ([]LabelCount, error) {
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabelCount
	for rows.Next() {
		var label any
		var lc LabelCount
		if err := rows.Scan(&label, &lc.Count); err != nil {
			return nil, err
		}
		switch v := label.(type) {
		case int64:
			lc.Label = strconv.FormatInt(v, 10)
		case string:
			lc.Label = v
		}
		out = append(out, lc)
	}
	return out, rows.Err()
}

// RecentFailures lists non-success, non-canceled requests by id desc.
// beforeID <= 0 means no cursor.
func (s *Store) RecentFailures(ctx context.Context, keyID string, r Range, beforeID int64, limit int) ([]Failure, error) {
	sub, args := scoped(&keyID, r)
	q := `SELECT id, ts, method, target_host, status, error_code, aborted, duration_ms, request_id, client_ip
		FROM ` + sub + ` WHERE cat IN ('relay','aborted','upstream')`
	if beforeID > 0 {
		q += ` AND id < ?`
		args = append(args, beforeID)
	}
	rows, err := s.r.QueryContext(ctx, q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Failure
	for rows.Next() {
		var f Failure
		var ts, dur int64
		var aborted int
		if err := rows.Scan(&f.ID, &ts, &f.Method, &f.TargetHost, &f.Status, &f.ErrorCode, &aborted, &dur, &f.RequestID, &f.ClientIP); err != nil {
			return nil, err
		}
		f.Time, f.Aborted, f.Duration = time.UnixMilli(ts), aborted == 1, time.Duration(dur)*time.Millisecond
		out = append(out, f)
	}
	return out, rows.Err()
}
