package netguard_test

import (
	"net/netip"
	"testing"

	"github.com/lllfx/DynamicAPIRelay/internal/netguard"
)

func TestIsPublic(t *testing.T) {
	pub := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"}
	priv := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "0.1.2.3", "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
		"224.0.0.1", "240.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "64:ff9b:1::1", "100::1",
		"2001:db8::1", "2002:7f00:1::", "2001::1"}
	for _, s := range pub {
		if !netguard.IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range priv {
		if netguard.IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should not be public", s)
		}
	}
	if netguard.IsPublic(netip.Addr{}) {
		t.Error("zero Addr should not be public")
	}
}
