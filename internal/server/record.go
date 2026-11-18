package server

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lllfx/DynamicAPIRelay/internal/reqctx"
	"github.com/lllfx/DynamicAPIRelay/internal/stats"
)

// Recorder receives one record per finished /v1/relay request.
type Recorder interface{ Record(stats.Record) }

// record emits a stats.Record after the request finishes, including when the
// stream is aborted by http.ErrAbortHandler.
func record(rec Recorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		info := reqctx.From(c.Request.Context())
		defer func() {
			v := recover()
			if v == http.ErrAbortHandler {
				info.Aborted = true
			}
			info.ClientCanceled = c.Request.Context().Err() != nil
			rec.Record(stats.Record{
				Time:           start,
				RequestID:      info.RequestID,
				KeyID:          info.KeyID,
				ClientIP:       info.ClientIP,
				Method:         c.Request.Method,
				TargetHost:     info.TargetHost,
				Status:         c.Writer.Status(),
				ErrorCode:      string(info.ErrorCode),
				Aborted:        info.Aborted,
				ClientCanceled: info.ClientCanceled,
				BytesIn:        atomic.LoadInt64(&info.BytesIn),
				BytesOut:       int64(max(c.Writer.Size(), 0)),
				Duration:       time.Since(start),
			})
			if v != nil {
				panic(v)
			}
		}()
		c.Next()
	}
}
