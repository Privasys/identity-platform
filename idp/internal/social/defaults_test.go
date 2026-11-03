package social

import (
	"slices"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/attributes"
)

// Each default provider's user-info endpoint and the claim map's identifier
// for that provider must agree: the endpoint decides which field carries
// the person's stable id, and the claim map must name that field. Changing
// one without the other would give returning people new accounts without
// any sign-in failing.
func TestDefaultProviders_IDClaimMatchesEndpoint(t *testing.T) {
	// What each endpoint names the person by.
	idFieldOf := map[string]string{
		"https://api.github.com/user":                   "id",
		"https://www.googleapis.com/oauth2/v3/userinfo": "sub",
		"https://graph.microsoft.com/v1.0/me":           "id",
		"https://api.linkedin.com/v2/userinfo":          "sub",
	}
	provs := DefaultProviders(Credentials{})
	if len(provs) != 4 {
		t.Fatalf("%d default providers", len(provs))
	}
	for _, p := range provs {
		want, known := idFieldOf[p.UserInfoURL]
		if !known {
			t.Errorf("%s: user-info endpoint %s is not in this test's table; add it with the field it names the person by", p.Name, p.UserInfoURL)
			continue
		}
		def, ok := attributes.Providers[p.Name]
		if !ok {
			t.Errorf("%s: no claim map", p.Name)
			continue
		}
		if def.IDClaim != want {
			t.Errorf("%s: claim map says the id is %q but %s names the person by %q", p.Name, def.IDClaim, p.UserInfoURL, want)
		}
		if !strings.HasPrefix(p.UserInfoURL, "https://") {
			t.Errorf("%s: user-info endpoint must be https", p.Name)
		}
	}
}

// A personal Microsoft account gets only the scopes the sign-in names, and
// Graph answers 403 to its /me without User.Read.
func TestDefaultProviders_MicrosoftAsksForUserRead(t *testing.T) {
	for _, p := range DefaultProviders(Credentials{}) {
		if p.Name != "microsoft" {
			continue
		}
		if !slices.Contains(p.Scopes, "User.Read") {
			t.Fatalf("scopes %v", p.Scopes)
		}
		return
	}
	t.Fatal("no microsoft provider")
}
