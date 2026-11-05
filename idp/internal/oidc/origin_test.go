package oidc

import (
	"net/http/httptest"
	"testing"

	"github.com/Privasys/idp/internal/clients"
)

const testIssuer = "https://privasys.id"

func TestSignInOrigin(t *testing.T) {
	for name, c := range map[string]struct{ header, param, want string }{
		"a page calling directly":            {"https://evil.example", "", "https://evil.example"},
		"a page cannot claim another origin": {"https://evil.example", "https://app.example", "https://evil.example"},
		"the frame reports its parent":       {testIssuer, "https://app.example", "https://app.example"},
		"a same-origin GET sends no Origin":  {"", "https://app.example", "https://app.example"},
		"nothing stated":                     {"", "", ""},
	} {
		r := httptest.NewRequest("GET", "/authorize?parent_origin="+c.param, nil)
		if c.header != "" {
			r.Header.Set("Origin", c.header)
		}
		if got := signInOrigin(r, testIssuer); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestClientOriginAllowed(t *testing.T) {
	client := &clients.Client{ClientID: "c1", RedirectURIs: []string{"https://app.example/"}}
	defer SetClientOriginEnforcement(false)
	for _, c := range []struct {
		origin  string
		enforce bool
	}{
		{"https://app.example", true},
		{testIssuer, true},
		{"", true},
		{"https://evil.example", false},
	} {
		SetClientOriginEnforcement(false)
		if !clientOriginAllowed(client, c.origin, testIssuer) {
			t.Errorf("%q must pass while only logging", c.origin)
		}
		SetClientOriginEnforcement(true)
		if got := clientOriginAllowed(client, c.origin, testIssuer); got != c.enforce {
			t.Errorf("%q enforced: %v, want %v", c.origin, got, c.enforce)
		}
	}
}
