package relay_test

import (
	"net/netip"
	"sync/atomic"
)

type netipAddr = netip.Addr

func atomicLoad(p *int64) int64 { return atomic.LoadInt64(p) }
