package oidc

import (
	"slices"
	"testing"

	"github.com/Privasys/idp/internal/clients"
)

// A platform client's whitelist is a ceiling: a priced key on it reaches the
// wallet only when the request names it, whatever the scope. A relying party
// keeps the registration-naming it was migrated onto.
func TestPlatformClientPricedKeysOnlyWhenNamed(t *testing.T) {
	wl := []string{"email", "name", "given_name_id", "birthdate_id", "age_over_18"}
	platform := &clients.Client{ClientID: "privasys-platform", Platform: true, RequiredAttributes: wl}
	rp := &clients.Client{ClientID: "rp", RequiredAttributes: wl}

	got := requestedAttributes("openid email profile identity", nil, platform)
	for _, k := range []string{"given_name_id", "birthdate_id", "age_over_18"} {
		if slices.Contains(got, k) {
			t.Fatalf("platform client acquired %s by scope: %v", k, got)
		}
	}
	if !slices.Contains(got, "email") || !slices.Contains(got, "name") {
		t.Fatalf("free keys lost: %v", got)
	}
	if got := requestedAttributes("openid", []string{"given_name_id"}, platform); !slices.Contains(got, "given_name_id") {
		t.Fatalf("a named priced key was dropped: %v", got)
	}
	if got := requestedAttributes("openid identity", nil, rp); !slices.Contains(got, "birthdate_id") {
		t.Fatalf("a relying party lost its registration-named key: %v", got)
	}
}
