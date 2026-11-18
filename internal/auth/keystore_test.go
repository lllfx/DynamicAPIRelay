package auth_test

import (
	"strings"
	"testing"

	"github.com/lllfx/DynamicAPIRelay/internal/auth"
)

func TestAuthenticate(t *testing.T) {
	s := auth.NewKeyStore(map[string]string{"alice": strings.Repeat("a", 32), "bob": strings.Repeat("b", 32)})
	cases := []struct {
		in     string
		wantID string
		wantOK bool
	}{
		{strings.Repeat("b", 32), "bob", true},
		{strings.Repeat("a", 32), "alice", true},
		{"", "", false},
		{strings.Repeat("a", 31), "", false},
		{strings.Repeat("a", 32) + "x", "", false},
	}
	for _, c := range cases {
		id, ok := s.Authenticate(c.in)
		if id != c.wantID || ok != c.wantOK {
			t.Errorf("Authenticate(%q) = (%q,%v) want (%q,%v)", c.in, id, ok, c.wantID, c.wantOK)
		}
	}
}
