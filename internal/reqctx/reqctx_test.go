package reqctx_test

import (
	"context"
	"testing"

	"github.com/lllfx/DynamicAPIRelay/internal/reqctx"
)

func TestReqctxFromMissingReturnsEmpty(t *testing.T) {
	if reqctx.From(context.Background()) == nil {
		t.Fatal("From returned nil")
	}
	info := &reqctx.Info{RequestID: "req_x"}
	if got := reqctx.From(reqctx.With(context.Background(), info)); got != info {
		t.Fatalf("got %p want %p", got, info)
	}
}
