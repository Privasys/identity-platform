// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"testing"

	"github.com/Privasys/idp/internal/clients"
)

func TestAttributeRequirements(t *testing.T) {
	// Client with a required_attributes whitelist: those are essential.
	cli := &clients.Client{RequiredAttributes: []string{"email", "name"}}
	req := attributeRequirements("openid email profile", nil, cli)
	if !req["email"].Essential || !req["name"].Essential {
		t.Errorf("email/name should be essential for a whitelisted client: %+v", req)
	}
	if req["email"].Assurance != "any" {
		t.Errorf("email assurance = %q, want any", req["email"].Assurance)
	}

	// No whitelist: falls back to the email+name baseline; extras optional.
	open := attributeRequirements("openid email profile", nil, &clients.Client{})
	if !open["email"].Essential || !open["name"].Essential {
		t.Errorf("email/name should be essential by default: %+v", open)
	}
	if open["given_name"].Essential {
		t.Errorf("given_name should be optional by default")
	}

	// identity scope → gov assurance on the KYC attributes.
	id := attributeRequirements("openid identity", nil, &clients.Client{})
	for _, k := range []string{"birthdate", "nationality", "age_over_18", "age_over_21"} {
		if id[k].Assurance != "gov" {
			t.Errorf("%s assurance = %q, want gov", k, id[k].Assurance)
		}
		if id[k].Essential {
			t.Errorf("%s should be optional when not in the whitelist", k)
		}
	}
}

// The correction the '_id' convention exists for: a name the holder typed and a
// name a passport certifies are two attributes, not one attribute at two prices.
// given_name stays free and self-asserted forever; given_name_id is the priced
// government-backed key, and a client reaches it by naming it.
func TestGivenNameAndItsGovTwinAreSeparateKeys(t *testing.T) {
	cli := &clients.Client{RequiredAttributes: []string{"email", "given_name", "given_name_id"}}

	// Self-asserted: straight out of the profile, free.
	self := attributeRequirements("openid email profile", nil, cli)
	if self["given_name"].Assurance != "any" {
		t.Errorf("given_name assurance = %q, want any", self["given_name"].Assurance)
	}
	if keys := reservableMarketplaceKeys(self); len(keys) != 0 {
		t.Errorf("given_name reserved %v; a self-asserted key must disclose free", keys)
	}
	if _, ok := self["given_name_id"]; ok {
		t.Error("given_name_id rode in on the profile scope; it is request-only")
	}

	// Gov: named on the request, namespaced under the field the enclave meters.
	gov := attributeRequirements("openid email profile", []string{"given_name_id"}, cli)
	if gov["given_name_id"].Assurance != "gov" {
		t.Errorf("given_name_id assurance = %q, want gov", gov["given_name_id"].Assurance)
	}
	keys := reservableMarketplaceKeys(gov)
	if len(keys) != 1 || keys[0] != "privasys:given_name" {
		t.Errorf("given_name_id reserved %v, want [privasys:given_name]", keys)
	}
}

// A named key must clear the client's whitelist too. A registration is a ceiling:
// a client that declared it needs an email cannot acquire a passport disclosure
// by adding a query parameter.
func TestNamedAttributesCannotEscapeTheWhitelist(t *testing.T) {
	cli := &clients.Client{RequiredAttributes: []string{"email"}}
	got := requestedAttributes("openid email", []string{"given_name_id", "birthdate_id"}, cli)
	for _, k := range got {
		if k == "given_name_id" || k == "birthdate_id" {
			t.Errorf("%s escaped the required_attributes whitelist", k)
		}
	}
}

// A client with no whitelist may name what it likes — that is the whole point of
// the per-attribute path for a dynamically registered relying party — but it only
// gets what it actually named.
func TestNamedAttributesReachRequestOnlyKeys(t *testing.T) {
	got := requestedAttributes("openid email", []string{"birthdate_id"}, &clients.Client{})
	found := false
	for _, k := range got {
		if k == "birthdate_id" {
			found = true
		}
		if k == "nationality_id" {
			t.Error("nationality_id arrived without being named")
		}
	}
	if !found {
		t.Error("birthdate_id was not reachable by naming it")
	}
}

// Unknown keys are dropped, not fatal: the parameter is filled from a referential
// the relying party fetched itself, which may be newer than this build. A sign-in
// that fails outright is a worse answer than one missing an attribute the client
// can see is absent.
func TestParseAttributesParam(t *testing.T) {
	got := parseAttributesParam("given_name_id, birthdate_id no_such_attribute given_name_id")
	if len(got) != 2 || got[0] != "given_name_id" || got[1] != "birthdate_id" {
		t.Errorf("parsed %v, want [given_name_id birthdate_id]", got)
	}
	if parseAttributesParam("") != nil {
		t.Error("an absent parameter must parse to nil, not an empty request")
	}
}

// The failure mode that was found and defused once already: a relying party that
// declares no whitelist and asks for `identity` must get the identity baseline it
// has always got, and NOT the newly billable attributes. Reintroducing this is a
// silent charge for something nobody requested.
func TestIdentityScopeWithoutWhitelistPullsNoRequestOnlyAttribute(t *testing.T) {
	open := requestedAttributes("openid identity", nil, &clients.Client{})
	got := map[string]bool{}
	for _, k := range open {
		got[k] = true
	}
	for _, k := range []string{
		"given_name_id", "family_name_id", "birthdate_id", "nationality_id",
		"picture_id", "age_band", "document_valid",
	} {
		if got[k] {
			t.Errorf("%s was pulled into a whitelist-less identity request", k)
		}
	}
	// The pre-existing identity baseline is untouched.
	for _, k := range []string{"birthdate", "nationality", "age_over_18", "age_over_21", "document_number"} {
		if !got[k] {
			t.Errorf("%s dropped out of the identity baseline", k)
		}
	}
	// And that baseline reserves exactly what it always reserved.
	reqs := attributeRequirements("openid identity", nil, &clients.Client{})
	keys := reservableMarketplaceKeys(reqs)
	want := []string{"privasys:age_over_18", "privasys:age_over_21", "privasys:birthdate", "privasys:nationality"}
	if len(keys) != len(want) {
		t.Fatalf("identity baseline reserved %v, want %v", keys, want)
	}
	for i, k := range want {
		if keys[i] != k {
			t.Fatalf("identity baseline reserved %v, want %v", keys, want)
		}
	}
}

// An ordinary profile-scope request must return exactly what it always did, for
// clients with a whitelist and without. Adding a government-backed twin is only a
// new capability if nothing about the old key moved.
func TestProfileScopeRequestIsUnchanged(t *testing.T) {
	open := requestedAttributes("openid email profile", nil, &clients.Client{})
	want := []string{"sub", "email", "name", "given_name", "family_name", "nickname", "picture", "locale"}
	if len(open) != len(want) {
		t.Fatalf("profile request = %v, want %v", open, want)
	}
	for i, k := range want {
		if open[i] != k {
			t.Fatalf("profile request = %v, want %v", open, want)
		}
	}
}

// A key and its legacy spelling are one disclosure under two names and share one
// registry row. A client naming both must be charged once, not twice.
func TestSupersededSpellingIsNotChargedTwice(t *testing.T) {
	cli := &clients.Client{RequiredAttributes: []string{"birthdate", "birthdate_id"}}
	reqs := attributeRequirements("openid identity", []string{"birthdate_id"}, cli)
	keys := reservableMarketplaceKeys(reqs)
	if len(keys) != 1 || keys[0] != "privasys:birthdate" {
		t.Errorf("reserved %v, want [privasys:birthdate] exactly once", keys)
	}
}

// The ceremony is priced by migration 056 but deliberately absent from the
// referential, so nothing there can carry its marketplace key. It was silently
// reserving nothing — a live biometric check run for free — until the minter
// stopped synthesising `privasys:`+key.
func TestPresenceCeremonyIsStillReserved(t *testing.T) {
	reqs := map[string]AttributeRequirement{
		presenceAttribute: {Essential: true, Assurance: "gov"},
	}
	got := reservableMarketplaceKeys(reqs)
	if len(got) != 1 || got[0] != "privasys:holder_present" {
		t.Errorf("reserved %v, want [privasys:holder_present]", got)
	}
}

// A gov attribute with no registry row must never be namespaced. Reserving an
// unknown key fails the whole authorization, so the fields the enclave certifies
// but the marketplace has not priced have to fall out here.
func TestUnpricedGovFieldsAreNotReserved(t *testing.T) {
	reqs := map[string]AttributeRequirement{
		"doc_expiry":      {Assurance: "gov"},
		"place_of_birth":  {Assurance: "gov"},
		"personal_number": {Assurance: "gov"},
		"picture_id":      {Assurance: "gov"},
		"document_number": {Assurance: "gov"},
	}
	if got := reservableMarketplaceKeys(reqs); len(got) != 0 {
		t.Errorf("reserved %v for attributes with no registry row", got)
	}
}

// A disclosure the client named must survive the token endpoint's filter. Without
// the named set threaded onto the auth code it would be dropped one step before
// the ID token, after the wallet did the work and the relying party paid for it.
func TestNamedAttributeSurvivesTheTokenFilter(t *testing.T) {
	attrs := map[string]string{"given_name_id": "BERTRAND", "sex": "M"}
	got := filterAttributesRequested(attrs, "openid email profile", []string{"given_name_id"})
	if got["given_name_id"] != "BERTRAND" {
		t.Error("a named request-only attribute was filtered out of the token")
	}
	if _, ok := got["sex"]; ok {
		t.Error("sex arrived without the identity scope or a naming")
	}
}
