package oidc

import "testing"

// A government-backed key reaches the relying party only as a signed
// disclosure; a plain value the wallet sent in its place is dropped.
func TestGovKeyNeedsADisclosureToken(t *testing.T) {
	token := "eyJhbGciOiJFUzI1NiJ9.eyJ2YWx1ZSI6dHJ1ZX0.c2ln~"
	got := filterAttributesRequested(map[string]string{
		"age_over_18":   "true",
		"given_name_id": token,
		"name":          "A Visitor",
	}, "openid", []string{"age_over_18", "given_name_id", "name"})
	if _, ok := got["age_over_18"]; ok {
		t.Fatalf("a plain value passed as a government-backed key: %v", got)
	}
	if got["given_name_id"] != token || got["name"] != "A Visitor" {
		t.Fatalf("a disclosure or a self-asserted value was dropped: %v", got)
	}
}
