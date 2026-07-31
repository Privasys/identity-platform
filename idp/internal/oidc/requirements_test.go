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

	// A key the scope reaches but the whitelist does not name is not requested
	// at all, so there is no "optional extra" tier: the whitelist is the request.
	if _, ok := req["given_name"]; ok {
		t.Errorf("given_name rode in on the profile scope past the whitelist: %+v", req)
	}

	// identity scope → gov assurance on the KYC attributes. birthdate and
	// nationality are no longer among them: the bare spelling is the
	// self-asserted half of a pair now.
	id := attributeRequirements("openid identity", nil,
		&clients.Client{RequiredAttributes: []string{"age_over_18", "age_over_21"}})
	for _, k := range []string{"age_over_18", "age_over_21"} {
		if id[k].Assurance != "gov" {
			t.Errorf("%s assurance = %q, want gov", k, id[k].Assurance)
		}
		if !id[k].Essential {
			t.Errorf("%s: a whitelisted attribute is essential", k)
		}
	}
}

// Naming attributes is how a relying party declares it consumes any, so a client
// that names none receives none — never everything its runtime scope reaches.
// Registration refuses such a client outright; this is the runtime half, which
// has to hold for a row that predates the rule.
func TestClientWithoutAWhitelistReceivesNothing(t *testing.T) {
	for _, scope := range []string{"openid email profile", "openid identity", "openid"} {
		got := requestedAttributes(scope, nil, &clients.Client{})
		if len(got) != 1 || got[0] != "sub" {
			t.Errorf("scope %q without a whitelist = %v, want [sub]", scope, got)
		}
		if reqs := attributeRequirements(scope, nil, &clients.Client{}); len(reqs) != 0 {
			t.Errorf("scope %q without a whitelist required %+v", scope, reqs)
		}
	}
	// Nor can naming a key on the request stand in for the registration.
	got := requestedAttributes("openid identity", []string{"birthdate_id", "email"}, &clients.Client{})
	if len(got) != 1 || got[0] != "sub" {
		t.Errorf("named attributes without a whitelist = %v, want [sub]", got)
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

// Naming a key on the request is how a client reaches a request-only attribute
// its whitelist admits: no spelling of the scope carries one. It still gets only
// what it actually named, so a whitelist is a menu rather than an order.
func TestNamedAttributesReachRequestOnlyKeys(t *testing.T) {
	cli := &clients.Client{RequiredAttributes: []string{"email", "birthdate_id", "nationality_id"}}
	got := requestedAttributes("openid email", []string{"birthdate_id"}, cli)
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
// whitelists the free identity baseline and asks for `identity` must get exactly
// that baseline, and NOT the newly billable attributes. Reintroducing this is a
// silent charge for something nobody requested.
func TestIdentityScopePullsNoRequestOnlyAttribute(t *testing.T) {
	baseline := &clients.Client{RequiredAttributes: []string{
		"birthdate", "nationality", "age_over_18", "age_over_21", "document_number",
	}}
	open := requestedAttributes("openid identity", nil, baseline)
	got := map[string]bool{}
	for _, k := range open {
		got[k] = true
	}
	for _, k := range []string{
		"given_name_id", "family_name_id", "birthdate_id", "nationality_id",
		"picture_id", "age_band", "document_valid",
		// Priced by migration 076 and made request-only in the same change:
		// they rode the scope for free before, and a priced key on a
		// scope-derived set is a charge nobody asked for.
		"doc_expiry", "place_of_birth", "personal_number",
	} {
		if got[k] {
			t.Errorf("%s was pulled into a whitelist-less identity request", k)
		}
	}
	// The free half of the identity baseline is untouched. birthdate and
	// nationality are still here — self-asserted now, which is the deliberate
	// break — and the document fields the marketplace does not price still ride
	// the scope.
	for _, k := range []string{"birthdate", "nationality", "age_over_18", "age_over_21", "document_number"} {
		if !got[k] {
			t.Errorf("%s dropped out of the identity baseline", k)
		}
	}
	// The baseline now reserves only the two age insights: the passport readings
	// of a birth date and a nationality moved to keys a client must name.
	reqs := attributeRequirements("openid identity", nil, baseline)
	keys := reservableMarketplaceKeys(reqs)
	want := []string{"privasys:age_over_18", "privasys:age_over_21"}
	if len(keys) != len(want) {
		t.Fatalf("identity baseline reserved %v, want %v", keys, want)
	}
	for i, k := range want {
		if keys[i] != k {
			t.Fatalf("identity baseline reserved %v, want %v", keys, want)
		}
	}
}

// An ordinary profile-scope request must return exactly what it always did.
// Adding a government-backed twin is only a new capability if nothing about the
// old key moved: same keys, same order, all still free and self-asserted.
func TestProfileScopeRequestIsUnchanged(t *testing.T) {
	want := []string{"sub", "email", "name", "given_name", "family_name", "nickname", "picture", "locale"}
	cli := &clients.Client{RequiredAttributes: want[1:]}
	open := requestedAttributes("openid email profile", nil, cli)
	if len(open) != len(want) {
		t.Fatalf("profile request = %v, want %v", open, want)
	}
	for i, k := range want {
		if open[i] != k {
			t.Fatalf("profile request = %v, want %v", open, want)
		}
	}
	if keys := reservableMarketplaceKeys(attributeRequirements("openid email profile", nil, cli)); len(keys) != 0 {
		t.Errorf("a profile request reserved %v; every profile key is free", keys)
	}
}

// A pair is two keys over ONE registry row. A client that names both halves is
// asking for one disclosure at two trust levels, and must be charged once.
func TestBothSpellingsOfAPairAreChargedOnce(t *testing.T) {
	cli := &clients.Client{RequiredAttributes: []string{"birthdate", "birthdate_id"}}
	reqs := attributeRequirements("openid identity", []string{"birthdate_id"}, cli)
	keys := reservableMarketplaceKeys(reqs)
	if len(keys) != 1 || keys[0] != "privasys:birthdate" {
		t.Errorf("reserved %v, want [privasys:birthdate] exactly once", keys)
	}
}

// The migration's whole promise, from the relying party's side.
//
// A client registered before the split whitelisted `birthdate` and asked for the
// identity scope, and what it got was a passport-certified date. The store
// migration rewrites that whitelist to `birthdate_id`; this is the assertion that
// the rewrite is worth anything — the client cannot change the request it sends,
// so if a whitelisted request-only key were unreachable, migrating it would take
// a government-verified disclosure and leave nothing in its place.
func TestMigratedClientStillReceivesGovernmentAssurance(t *testing.T) {
	// What the client sent before the split, and what it got.
	before := &clients.Client{RequiredAttributes: []string{"email", "birthdate", "nationality"}}
	// The same client after the store migration rewrote its whitelist. Same
	// request: same scope, no `attributes` parameter, nothing it had to redeploy.
	after := &clients.Client{RequiredAttributes: []string{"email", "birthdate_id", "nationality_id"}}

	reqs := attributeRequirements("openid email identity", nil, after)
	for _, k := range []string{"birthdate_id", "nationality_id"} {
		if reqs[k].Assurance != "gov" {
			t.Errorf("%s assurance = %q, want gov", k, reqs[k].Assurance)
		}
		if !reqs[k].Essential {
			t.Errorf("%s: a whitelisted attribute is essential", k)
		}
	}
	if _, ok := reqs["birthdate"]; ok {
		t.Error("the self-asserted birthdate rode in on the scope; the whitelist no longer allows it")
	}

	// And it reserves exactly what it reserved before the split: the same two
	// registry rows, under the spelling the enclave meters. Restated rather than
	// recomputed from `before`, because the pre-migration reservation cannot be
	// derived from a referential in which the bare keys are already free.
	want := []string{"privasys:birthdate", "privasys:nationality"}
	got := reservableMarketplaceKeys(reqs)
	if len(got) != len(want) {
		t.Fatalf("migrated client reserves %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("migrated client reserves %v, want %v", got, want)
		}
	}
	if keys := reservableMarketplaceKeys(attributeRequirements("openid email identity", nil, before)); len(keys) != 0 {
		t.Errorf("the un-migrated client reserves %v; its whitelist now names two free keys", keys)
	}
}

// The other half of the split: naming the bare key from now on means the
// self-asserted value, free. A client that registers today and asks for
// "birthdate" is asking for a date the holder typed, and billing it for a
// passport ceremony it never requested is the failure this whole model removes.
func TestNewClientNamingTheBareKeyIsSelfAssertedAndFree(t *testing.T) {
	cli := &clients.Client{RequiredAttributes: []string{"email", "birthdate", "nationality"}}
	reqs := attributeRequirements("openid email identity", nil, cli)
	for _, k := range []string{"birthdate", "nationality"} {
		if reqs[k].Assurance != "any" {
			t.Errorf("%s assurance = %q, want any", k, reqs[k].Assurance)
		}
	}
	if keys := reservableMarketplaceKeys(reqs); len(keys) != 0 {
		t.Errorf("reserved %v; a self-asserted key must disclose free", keys)
	}
}

// A whitelist is a registration, not a request parameter, so it names a
// request-only key only where the scope would have carried it. Without the scope
// clause a client whitelisting a passport key would be charged on every sign-in,
// including the ones that never asked for identity at all.
func TestRegistrationNamesRequestOnlyKeysOnlyWithinTheScope(t *testing.T) {
	cli := &clients.Client{RequiredAttributes: []string{"email", "birthdate_id"}}

	got := map[string]bool{}
	for _, k := range requestedAttributes("openid email", nil, cli) {
		got[k] = true
	}
	if got["birthdate_id"] {
		t.Error("birthdate_id was requested without the identity scope")
	}

	got = map[string]bool{}
	for _, k := range requestedAttributes("openid email identity", nil, cli) {
		got[k] = true
	}
	if !got["birthdate_id"] {
		t.Error("birthdate_id was not reachable from the registration that names it")
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
		"document_number": {Assurance: "gov"},
		"document_type":   {Assurance: "gov"},
		"issuing_state":   {Assurance: "gov"},
		"sex":             {Assurance: "gov"},
	}
	if got := reservableMarketplaceKeys(reqs); len(got) != 0 {
		t.Errorf("reserved %v for attributes with no registry row", got)
	}
}

// The other direction, for the four migration 076 seeded: a certified field the
// registry now prices must reserve, or the enclave meters a disclosure against a
// voucher that never authorised it.
func TestNewlyPricedCertifiedFieldsAreReserved(t *testing.T) {
	reqs := map[string]AttributeRequirement{
		"doc_expiry":      {Assurance: "gov"},
		"place_of_birth":  {Assurance: "gov"},
		"personal_number": {Assurance: "gov"},
		"picture_id":      {Assurance: "gov"},
	}
	want := []string{
		"privasys:doc_expiry", "privasys:personal_number",
		"privasys:picture_id", "privasys:place_of_birth",
	}
	got := reservableMarketplaceKeys(reqs)
	if len(got) != len(want) {
		t.Fatalf("reserved %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reserved %v, want %v", got, want)
		}
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
