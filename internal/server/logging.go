package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
	"github.com/lllfx/DynamicAPIRelay/internal/reqctx"
)

// requestContext assigns a request ID, resolves the client IP via trusted
// proxies, and emits one sanitized access log line (even if a handler panics).
func requestContext(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		info := &reqctx.Info{RequestID: relayerr.NewRequestID(), ClientIP: c.ClientIP()}
		c.Request = c.Request.WithContext(reqctx.With(c.Request.Context(), info))
		c.Header(relayerr.HeaderRequestID, info.RequestID)
		defer func() {
			log.Info("request",
				"request_id", info.RequestID,
				"key_id", info.KeyID,
				"client_ip", info.ClientIP,
				"method", c.Request.Method,
				"target_host", info.TargetHost,
				"status", c.Writer.Status(),
				"bytes_in", atomic.LoadInt64(&info.BytesIn),
				"bytes_out", max(c.Writer.Size(), 0),
				"duration_ms", time.Since(start).Milliseconds(),
				"error_code", string(info.ErrorCode),
			)
		}()
		c.Next()
	}
}

// recoverer lets http.ErrAbortHandler propagate so net/http silently aborts
// the connection; any other panic becomes a 500 INTERNAL_ERROR if possible.
func recoverer(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			info := reqctx.From(c.Request.Context())
			log.Error("handler panic", "request_id", info.RequestID, "panic", fmt.Sprint(v))
			if !c.Writer.Written() {
				abortWith(c, relayerr.Internal)
			}
			c.Abort()
		}()
		c.Next()
	}
}

func abortWith(c *gin.Context, code relayerr.Code) {
	info := reqctx.From(c.Request.Context())
	info.ErrorCode = code
	relayerr.Write(c.Writer, info.RequestID, relayerr.New(code))
	c.Abort()
}
