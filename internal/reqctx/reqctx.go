// Package reqctx carries mutable per-request relay metadata through a context.
package reqctx

import (
	"context"

	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
)

// Info is filled in by middleware and the relay handler, then read by the access log.
type Info struct {
	RequestID  string
	KeyID      string
	TargetHost string
	ErrorCode  relayerr.Code
}

type ctxKey struct{}

// With returns a context carrying info.
func With(ctx context.Context, info *Info) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

// From returns the Info in ctx, or a fresh empty Info if none is present.
func From(ctx context.Context) *Info {
	if info, ok := ctx.Value(ctxKey{}).(*Info); ok && info != nil {
		return info
	}
	return &Info{}
}
