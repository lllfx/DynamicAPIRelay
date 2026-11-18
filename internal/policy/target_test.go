package policy_test

import (
	"strings"
	"testing"

	"github.com/lllfx/DynamicAPIRelay/internal/policy"
	"github.com/lllfx/DynamicAPIRelay/internal/relayerr"
)

func TestParse(t *testing.T) {
	p := policy.Default()
	cases := []struct {
		raw  string
		want relayerr.Code
	}{
		{"https://api.example.com/v1/messages?mode=test", ""},
		{"https://API.Example.com:443/x", ""},
		{"https://xn--fiqs8s.example/", ""},
		{"https://api.example.com", ""},
		{"", relayerr.TargetInvalid},
		{"/relative", relayerr.TargetInvalid},
		{"https://u:p@api.example.com/", relayerr.TargetInvalid},
		{"https://api.example.com/#frag", relayerr.TargetInvalid},
		{"https://api.example.com/a%zz", relayerr.TargetInvalid},
		{"https://api.example.com/a%2", relayerr.TargetInvalid},
		{"https://api.example.com/a b", relayerr.TargetInvalid},
		{"https://api.example.com/\x01", relayerr.TargetInvalid},
		{"https://api.example.com/\x7f", relayerr.TargetInvalid},
		{"https://api.example.com./", relayerr.TargetInvalid},
		{"https://-bad.example.com/", relayerr.TargetInvalid},
		{"https://bücher.example/", relayerr.TargetInvalid},
		{"https://api..example.com/", relayerr.TargetInvalid},
		{"https:api.example.com", relayerr.TargetInvalid},
		{"https://example.com/" + strings.Repeat("a", 4100), relayerr.TargetInvalid},
		{"http://api.example.com/", relayerr.TargetForbidden},
		{"ftp://api.example.com/", relayerr.TargetForbidden},
		{"https://127.0.0.1/", relayerr.TargetForbidden},
		{"https://[::1]/", relayerr.TargetForbidden},
		{"https://localhost/", relayerr.TargetForbidden},
		{"https://foo.localhost/", relayerr.TargetForbidden},
		{"https://0x7f.0.0.1/", relayerr.TargetForbidden},
		{"https://2130706433/", relayerr.TargetForbidden},
		{"https://10.0.0.1.example.com/", ""},
		{"https://api.example.com:8443/", relayerr.TargetForbidden},
		{"https://api.example.com:/", relayerr.TargetForbidden},
	}
	for _, c := range cases {
		u, err := p.Parse(c.raw)
		var got relayerr.Code
		if err != nil {
			got = err.Code
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %q want %q", c.raw, got, c.want)
		}
		if err == nil && u == nil {
			t.Errorf("Parse(%q): nil URL without error", c.raw)
		}
	}
}

func TestParseCanonicalizes(t *testing.T) {
	u, err := policy.Default().Parse("https://API.Example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "api.example.com:443" || u.Path != "/" {
		t.Errorf("host=%q path=%q", u.Host, u.Path)
	}
}

func TestParsePreservesEncoding(t *testing.T) {
	u, err := policy.Default().Parse("https://api.example.com/a%2Fb/c?sig=a+b%20c&x=%3D")
	if err != nil {
		t.Fatal(err)
	}
	if u.EscapedPath() != "/a%2Fb/c" || u.RawQuery != "sig=a+b%20c&x=%3D" {
		t.Errorf("escaped=%q rawquery=%q", u.EscapedPath(), u.RawQuery)
	}
}

func TestAllowedPortOverride(t *testing.T) {
	p := policy.TargetPolicy{AllowedPort: "8443", MaxLength: 4096}
	if _, err := p.Parse("https://api.example.com:8443/"); err != nil {
		t.Errorf("unexpected %v", err)
	}
	if _, err := p.Parse("https://api.example.com/"); err == nil || err.Code != relayerr.TargetForbidden {
		t.Errorf("implicit 443 should be forbidden when AllowedPort=8443, got %v", err)
	}
}
