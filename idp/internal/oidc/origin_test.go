package oidc

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
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

// The frame asks before it gives a page a stored session: the client's own
// pages get a yes, any other page a yes only while the check is not enforced.
func TestHandleClientOrigin(t *testing.T) {
	reg, _, _ := newDeviceTestEnv(t)
	h := HandleClientOrigin(reg, testIssuer)
	defer SetClientOriginEnforcement(false)
	ask := func(clientID, origin string) bool {
		t.Helper()
		q := url.Values{"client_id": {clientID}, "origin": {origin}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/session/client-origin?"+q.Encode(), nil))
		var body struct{ Allowed bool }
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body.Allowed
	}
	for _, c := range []struct {
		client, origin    string
		logging, enforced bool
	}{
		{"privasys-cli", "https://privasys.id", true, true},
		{"privasys-cli", "https://evil.example", true, false},
		{"privasys-cli", "", false, false},
		{"no-such-client", "https://privasys.id", false, false},
	} {
		SetClientOriginEnforcement(false)
		if got := ask(c.client, c.origin); got != c.logging {
			t.Errorf("%s %q while logging: %v, want %v", c.client, c.origin, got, c.logging)
		}
		SetClientOriginEnforcement(true)
		if got := ask(c.client, c.origin); got != c.enforced {
			t.Errorf("%s %q enforced: %v, want %v", c.client, c.origin, got, c.enforced)
		}
	}
}
