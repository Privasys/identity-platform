// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package attributes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sharedDir is the single source of truth this package's embedded copies are
// generated from (see the go:generate lines in attributes.go).
const sharedDir = "../../../shared"

// The embedded copy is a build artefact of shared/canonical-attributes.json, and
// `go build` will happily ship a stale one: that is exactly how the IdP spent a
// month serving a referential missing ten identity attributes, silently
// rejecting them at client registration and downgrading their assurance. Byte
// equality is the assertion because the served referential is these bytes
// verbatim — formatting differences would reach relying parties too.
func TestEmbeddedCopyMatchesShared(t *testing.T) {
	want, err := os.ReadFile(filepath.Join(sharedDir, "canonical-attributes.json"))
	if err != nil {
		t.Fatalf("read shared canonical-attributes.json: %v", err)
	}
	if string(rawJSON) != string(want) {
		t.Fatalf("embedded canonical-attributes.json is stale (%d bytes vs %d in shared/).\n"+
			"Run `go generate ./...` in idp/ and commit the result.", len(rawJSON), len(want))
	}
}

// The value sets are copied by the same generate step and served the same way.
func TestEmbeddedReferentialMatchesShared(t *testing.T) {
	for _, name := range []string{"locale", "nationality"} {
		want, err := os.ReadFile(filepath.Join(sharedDir, "referential", name+".json"))
		if err != nil {
			t.Fatalf("read shared referential/%s.json: %v", name, err)
		}
		got, ok := ReferentialFile(name)
		if !ok {
			t.Fatalf("referential/%s.json missing from the embedded copy", name)
		}
		if string(got) != string(want) {
			t.Errorf("embedded referential/%s.json is stale; run `go generate ./...`", name)
		}
	}
}

// A marketplace key names the field the ENCLAVE meters, which for an '_id' key is
// its certified field: given_name_id is sold as privasys:given_name, because that
// is the string /prove/field puts on the meter and therefore the string the
// voucher must authorise. Reserving privasys:given_name_id would fail as an
// unknown attribute, and nothing has ever seeded such a row.
func TestMarketplaceKeysNameTheCertifiedField(t *testing.T) {
	for _, a := range All {
		if a.Marketplace == nil {
			continue
		}
		ns, name, ok := strings.Cut(a.Marketplace.Key, ":")
		if !ok {
			t.Errorf("%s: marketplace key %q is not namespaced", a.Key, a.Marketplace.Key)
			continue
		}
		if ns == "" {
			t.Errorf("%s: marketplace key %q has an empty namespace", a.Key, a.Marketplace.Key)
		}
		if name != a.CertifiedFieldName() {
			t.Errorf("%s: marketplace key names %q, want the certified field %q",
				a.Key, name, a.CertifiedFieldName())
		}
	}
}

// The set the marketplace prices, pinned. These keys are seeded by
// management-service migrations 055/056/076 in a repository with no build-time
// link to this one, so the only way a divergence gets noticed is a deliberate
// edit here. Adding a canonical attribute to the marketplace means adding its
// registry row in the same change, and in that order: a reservation naming a key
// with no row fails the whole authorization.
func TestMarketplaceIssuableSetIsPinned(t *testing.T) {
	want := map[string]string{
		"age_over_18":     "privasys:age_over_18",
		"age_over_21":     "privasys:age_over_21",
		"age_band":        "privasys:age_band",
		"document_valid":  "privasys:document_valid",
		"given_name_id":   "privasys:given_name",
		"family_name_id":  "privasys:family_name",
		"birthdate_id":    "privasys:birthdate",
		"nationality_id":  "privasys:nationality",
		"doc_expiry":      "privasys:doc_expiry",
		"place_of_birth":  "privasys:place_of_birth",
		"personal_number": "privasys:personal_number",
		"picture_id":      "privasys:picture_id",
	}
	got := map[string]string{}
	for _, a := range All {
		if a.Marketplace != nil {
			got[a.Key] = a.Marketplace.Key
		}
	}
	for key, w := range want {
		if got[key] != w {
			t.Errorf("%s: marketplace key = %q, want %q", key, got[key], w)
		}
		delete(got, key)
	}
	for key, g := range got {
		t.Errorf("%s is marked marketplace-issuable as %q with no registry row seeded for it", key, g)
	}
}

// A self-asserted key is never priced. This is the inconsistency the '_id'
// convention removes: given_name once sat in the profile scope carrying a
// marketplace block, so it was seeded and priced in the registry yet could never
// be billed through the OIDC path — the IdP assigned a profile-scope attribute
// assurance "any" and never namespaced it. The price now lives on given_name_id,
// which is unambiguously the passport disclosure.
func TestSelfAssertedKeysAreFree(t *testing.T) {
	for _, a := range All {
		if !a.IsGovVerified() && a.Marketplace != nil {
			t.Errorf("%s: self-asserted key is priced as %q", a.Key, a.Marketplace.Key)
		}
		// A value the enclave will not re-certify is relayed raw by the wallet;
		// charging marketplace money for a relayed value would sell an enclave
		// signature that was never produced.
		if a.Disclosure == "raw" && a.Marketplace != nil {
			t.Errorf("%s: raw-disclosure key is priced as %q", a.Key, a.Marketplace.Key)
		}
	}
}

// Pricing a key means making it request-only in the same change. A priced key on
// a scope-derived set charges every identity request for a disclosure nobody
// asked for, and a relying party out of credits gets a 402 instead of a sign-in.
//
// age_over_18/21 are exempt only because they predate the rule: they ARE the
// identity baseline, priced and scope-reachable since the marketplace shipped,
// and making them request-only now would drop them from every client that has
// ever asked for the identity scope.
func TestPricedKeysAreRequestOnly(t *testing.T) {
	baseline := map[string]bool{"age_over_18": true, "age_over_21": true}
	for _, a := range All {
		if a.Marketplace == nil || baseline[a.Key] {
			continue
		}
		if !a.RequestOnly {
			t.Errorf("%s is priced as %q but rides a scope; a client would be charged for naming nothing",
				a.Key, a.Marketplace.Key)
		}
	}
}

// The DG2 portrait is a certified disclosure now, not a relayed copy.
// identity-verifier v0.6.3 commits to it under its own salt, so prove_field
// opens it and meters privasys:picture_id, and migration 076 seeded that row;
// until both were true the wallet relayed its stored photo and there was no
// enclave signature to sell.
func TestPortraitDisclosesAsACertifiedToken(t *testing.T) {
	a, ok := ByKey["picture_id"]
	if !ok {
		t.Fatal("picture_id missing from the referential")
	}
	if a.Disclosure == "raw" {
		t.Error("picture_id: a raw key relays the wallet's copy and can never be billed")
	}
	// The enclave meters the field name it was handed; picture_id already IS
	// that name, so there is no certifiedField to translate.
	if got := a.CertifiedFieldName(); got != "picture_id" {
		t.Errorf("picture_id: certified field = %q, want picture_id", got)
	}
	if mk, ok := MarketplaceKey("picture_id"); !ok || mk != "privasys:picture_id" {
		t.Errorf("MarketplaceKey(picture_id) = %q, %v", mk, ok)
	}
}

// The pairing convention: a self-asserted key names its government-backed twin,
// the twin exists, is gov-verified, carries the '_id' suffix and is request-only.
// Request-only is the fail-closed half — a relying party that asks for `identity`
// and nothing else must never acquire a passport disclosure it did not name.
func TestGovTwinsArePairedAndRequestOnly(t *testing.T) {
	pairs := 0
	for _, a := range All {
		if a.GovKey == "" {
			continue
		}
		pairs++
		if a.IsGovVerified() {
			t.Errorf("%s: a key with a govKey must itself be self-asserted", a.Key)
		}
		twin, ok := ByKey[a.GovKey]
		if !ok {
			t.Errorf("%s: govKey %q is not a canonical attribute", a.Key, a.GovKey)
			continue
		}
		if twin.Key != a.Key+"_id" {
			t.Errorf("%s: govKey is %q, want %s_id", a.Key, twin.Key, a.Key)
		}
		if !twin.IsGovVerified() {
			t.Errorf("%s: twin %s is not gov-verified", a.Key, twin.Key)
		}
		if !twin.RequestOnly {
			t.Errorf("%s: twin %s must be request-only", a.Key, twin.Key)
		}
	}
	if pairs != 5 {
		t.Errorf("found %d self-asserted keys with a gov twin, want 5 "+
			"(given_name, family_name, picture, birthdate, nationality)", pairs)
	}

	// Every '_id' key must be request-only, including the ones with no
	// self-asserted twin to be named from. The suffix is the promise.
	for _, a := range All {
		if strings.HasSuffix(a.Key, "_id") && !a.RequestOnly {
			t.Errorf("%s: an _id key must be request-only", a.Key)
		}
	}
}

// birthdate and nationality predate the '_id' convention and were minted
// government-backed. They are now dual like every other pair, which is a
// BREAKING change and the reason this test is specific rather than generic:
// every clause is a way the split could be got wrong.
//
// The bare key keeps its scope and stays scope-reachable — making a shipped
// scope-reachable key request-only would drop it from every existing identity
// client — but it is self-asserted now, and therefore free. The passport reading
// moved to the '_id' twin.
func TestNewlyDualKeysAreSplitNotRetired(t *testing.T) {
	for key, want := range map[string]string{
		"birthdate":   "birthdate_id",
		"nationality": "nationality_id",
	} {
		a, ok := ByKey[key]
		if !ok {
			t.Fatalf("%s missing from the referential", key)
		}
		if a.GovKey != want {
			t.Errorf("%s: govKey = %q, want %q", key, a.GovKey, want)
		}
		if a.SupersededBy != "" {
			t.Errorf("%s: a dual key is not superseded by its twin; a picker must offer both", key)
		}
		if a.Scope != "identity" || a.IsGovVerified() {
			t.Errorf("%s: scope=%q gov=%v, want identity/false", key, a.Scope, a.IsGovVerified())
		}
		if a.RequestOnly {
			t.Errorf("%s: making a shipped scope-reachable key request-only would drop it from every existing identity client", key)
		}
		if mk, ok := MarketplaceKey(key); ok {
			t.Errorf("%s: the self-asserted half of a pair still prices as %q", key, mk)
		}
		// The twin keeps the registry row the bare key was sold under, so every
		// signed voucher and stored share link naming privasys:birthdate still
		// buys exactly the disclosure it always bought.
		if mk, _ := MarketplaceKey(want); mk != "privasys:"+key {
			t.Errorf("%s: marketplace key = %q, want privasys:%s", want, mk, key)
		}
	}
}

// Every identity-scope key states its assurance rather than leaning on the scope
// fallback. The fallback exists for an older copy of the document; a key added
// today that forgot the field would inherit gov assurance by accident here and
// self-asserted assurance in any reader that keys off the field alone.
func TestIdentityKeysStateTheirAssurance(t *testing.T) {
	for _, a := range All {
		if a.Scope == "identity" && a.Assurance == "" {
			t.Errorf("%s: identity-scope key does not state its assurance", a.Key)
		}
		if a.Assurance != "" && a.Assurance != SelfAsserted && a.Assurance != GovVerified {
			t.Errorf("%s: assurance %q is not registry vocabulary", a.Key, a.Assurance)
		}
	}
}

// InScope is what a scope-derived attribute set is built from, so a request-only
// key must be invisible to it no matter which scope it declares.
func TestInScopeExcludesRequestOnly(t *testing.T) {
	if !ByKey["birthdate"].InScope("openid identity") {
		t.Error("birthdate must stay reachable from the identity scope")
	}
	if ByKey["birthdate"].InScope("openid email profile") {
		t.Error("birthdate resolved without the identity scope")
	}
	for _, key := range []string{"given_name_id", "birthdate_id", "age_band", "picture_id"} {
		if ByKey[key].InScope("openid identity") {
			t.Errorf("%s: request-only key is reachable from a bare identity scope", key)
		}
	}
	if !ByKey["given_name"].InScope("openid profile") {
		t.Error("given_name must stay reachable from the profile scope")
	}
}

// The derived insights carry no stored value: the enclave computes them from the
// identity receipt at disclosure time. A wallet that treated them as profile
// fields would prompt the holder for an "age band" it can never type in.
func TestDerivedInsightsAreMarkedDerived(t *testing.T) {
	for _, key := range []string{"age_band", "document_valid"} {
		a, ok := ByKey[key]
		if !ok {
			t.Fatalf("%s missing from the referential", key)
		}
		if !a.Derived {
			t.Errorf("%s: not marked derived", key)
		}
		if !a.RequestOnly {
			t.Errorf("%s: a newly billable attribute must be request-only", key)
		}
	}
}

// The '_id' keys route to the passport commitment the enclave certified. The
// storage spelling is not a field the verifier ever saw, and prove_field rejects
// it as uncertified — which is exactly how a disclosure request for a
// gov-verified first name used to 400 and be silently dropped.
func TestCertifiedFieldsRouteToTheEnclaveSpelling(t *testing.T) {
	for key, want := range map[string]string{
		"given_name_id":  "given_name",
		"family_name_id": "family_name",
		"birthdate_id":   "birthdate",
		"nationality_id": "nationality",
		"doc_expiry":     "doc_expiry",
		"birthdate":      "birthdate",
	} {
		if got := ByKey[key].CertifiedFieldName(); got != want {
			t.Errorf("%s: certified field = %q, want %q", key, got, want)
		}
	}
}

// MarketplaceKey must refuse the identity attributes the marketplace does not
// price. Reserving one fails the whole authorization as an unknown attribute, so
// "not issuable" has to be distinguishable from "issuable under its own name".
// These four are certified by the enclave and returned alongside a priced
// insight, but no migration has seeded a row for them: they must stay unpriced
// here rather than be namespaced on the hope that a row exists.
func TestMarketplaceKeyRefusesUnpricedIdentityFields(t *testing.T) {
	for _, key := range []string{
		"document_number", "document_type", "issuing_state", "sex",
	} {
		a, ok := ByKey[key]
		if !ok {
			t.Fatalf("attribute %q missing from the referential", key)
		}
		if a.Scope != "identity" {
			t.Errorf("%q scope = %q, want identity", key, a.Scope)
		}
		if mk, ok := MarketplaceKey(key); ok {
			t.Errorf("%q resolved to marketplace key %q; it has no registry row", key, mk)
		}
	}
	if mk, ok := MarketplaceKey("age_over_18"); !ok || mk != "privasys:age_over_18" {
		t.Errorf("MarketplaceKey(age_over_18) = %q, %v", mk, ok)
	}
	if _, ok := MarketplaceKey("no_such_attribute"); ok {
		t.Error("MarketplaceKey resolved an attribute that does not exist")
	}
}

// The document fields the wallet writes after a chip read must be canonical, or
// the IdP rejects them at client registration and drops them from /userinfo.
// wallet/src/services/kyc.ts owns the other half of this list.
func TestDocumentAttributesAreCanonical(t *testing.T) {
	for _, key := range []string{
		"document_number", "document_type", "sex", "issuing_state", "doc_expiry",
		"place_of_birth", "personal_number", "given_name_id", "family_name_id",
		"picture_id", "birthdate_id", "nationality_id",
	} {
		a, ok := ByKey[key]
		if !ok {
			t.Errorf("document attribute %q missing from the referential", key)
			continue
		}
		if a.Scope != "identity" {
			t.Errorf("%q scope = %q, want identity", key, a.Scope)
		}
		if !a.IdentityVerifiable {
			t.Errorf("%q should be identityVerifiable", key)
		}
	}
}

// An older copy of the referential has no `assurance` field at all. It must still
// read the identity scope as government-backed: the served document is fetched at
// runtime by front ends that deploy on their own schedule, and a reader that
// defaulted to self-asserted would badge a passport disclosure as something the
// holder typed.
func TestAssuranceFallsBackToTheScope(t *testing.T) {
	legacy := Attribute{Key: "birthdate", Scope: "identity", IdentityVerifiable: true}
	if legacy.AssuranceLevel() != GovVerified {
		t.Errorf("legacy identity attribute reads as %q, want %q", legacy.AssuranceLevel(), GovVerified)
	}
	if (Attribute{Key: "nickname", Scope: "profile"}).AssuranceLevel() != SelfAsserted {
		t.Error("a profile attribute must read as self-asserted")
	}
}

// multiValued survives the round trip. It was documented in the referential and
// implemented in the wallet while the Go struct dropped it on the floor.
func TestMultiValuedIsDecoded(t *testing.T) {
	for _, key := range []string{"email", "phone_number"} {
		if !ByKey[key].MultiValued {
			t.Errorf("%q should be multiValued", key)
		}
	}
	if ByKey["name"].MultiValued {
		t.Error("name should not be multiValued")
	}
}
