// Package server wires the Gin router: health check, /v1/relay middleware
// chain (exact path, auth, limits, stats) and relay-style error responses.
package server

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/lllfx/DynamicAPIRelay/internal/auth"
	"github.com/lllfx/DynamicAPIRelay/internal/limiter"
	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
	"github.com/lllfx/DynamicAPIRelay/internal/reqctx"
)

// RelayPath is the only relay endpoint.
const RelayPath = "/v1/relay"

// HeaderKey carries the relay credential.
const HeaderKey = "X-Relay-Key"

var relayMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

// Deps are the router's collaborators.
type Deps struct {
	Auth           *auth.KeyStore
	Limiter        *limiter.Limiter
	Relay          http.Handler
	Logger         *slog.Logger
	Recorder       Recorder // nil = no stats
	TrustedProxies []string // CIDRs; empty = trust none
}

// NewRouter builds the Gin engine.
func NewRouter(d Deps) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	log := d.Logger
	if log == nil {
		log = slog.Default()
	}
	e := gin.New()
	e.RedirectTrailingSlash = false
	e.RedirectFixedPath = false
	e.HandleMethodNotAllowed = true
	e.RemoteIPHeaders = []string{"X-Forwarded-For"}
	var proxies []string
	if len(d.TrustedProxies) > 0 {
		proxies = d.TrustedProxies
	}
	if err := e.SetTrustedProxies(proxies); err != nil {
		return nil, err
	}

	e.Use(requestContext(log), recoverer(log))
	e.NoMethod(func(c *gin.Context) { abortWith(c, relayerr.MethodNotAllowed) })
	e.NoRoute(func(c *gin.Context) { abortWith(c, relayerr.NotFound) })
	e.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	var chain []gin.HandlerFunc
	if d.Recorder != nil {
		chain = append(chain, record(d.Recorder))
	}
	chain = append(chain, exactPath, authenticate(d.Auth), limit(d.Limiter), gin.WrapH(d.Relay))
	for _, m := range relayMethods {
		e.Handle(m, RelayPath, chain...)
	}
	return e, nil
}

// exactPath rejects encoded path variants and any query on the relay URL.
func exactPath(c *gin.Context) {
	u := c.Request.URL
	if u.EscapedPath() != RelayPath || u.RawQuery != "" || u.ForceQuery {
		abortWith(c, relayerr.RequestInvalid)
	}
}

func authenticate(ks *auth.KeyStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		vals := c.Request.Header.Values(HeaderKey)
		if len(vals) != 1 {
			abortWith(c, relayerr.AuthFailed)
			return
		}
		id, ok := ks.Authenticate(vals[0])
		if !ok {
			abortWith(c, relayerr.AuthFailed)
			return
		}
		reqctx.From(c.Request.Context()).KeyID = id
	}
}

func limit(l *limiter.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		info := reqctx.From(c.Request.Context())
		release, err := l.Acquire(info.KeyID)
		if err != nil {
			abortWith(c, err.Code)
			return
		}
		defer release()
		c.Next()
	}
}
