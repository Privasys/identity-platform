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

// Every marketplace key must be the namespaced spelling of its own attribute.
// The reservation matches on this string and a billing grant must repeat it
// exactly, so a typo here is a 402 for a relying party that can in fact pay.
func TestMarketplaceKeysAreNamespacedSelves(t *testing.T) {
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
		if name != a.Key {
			t.Errorf("%s: marketplace key names %q, not the canonical key", a.Key, name)
		}
		if a.Marketplace.Assurance == "" {
			t.Errorf("%s: marketplace entry has no assurance", a.Key)
		}
	}
}

// The set the marketplace prices, pinned. These keys are seeded by
// management-service migrations 055/056 in a repository with no build-time link
// to this one, so the only way a divergence gets noticed is a deliberate edit
// here. Adding a canonical attribute to the marketplace means adding its
// registry row in the same change.
func TestMarketplaceIssuableSetIsPinned(t *testing.T) {
	want := map[string]string{
		"given_name":  "privasys:given_name",
		"family_name": "privasys:family_name",
		"birthdate":   "privasys:birthdate",
		"nationality": "privasys:nationality",
		"age_over_18": "privasys:age_over_18",
		"age_over_21": "privasys:age_over_21",
	}
	got := map[string]string{}
	for _, a := range All {
		if a.Marketplace != nil {
			got[a.Key] = a.Marketplace.Key
		}
	}
	for key, mk := range want {
		if got[key] != mk {
			t.Errorf("%s: marketplace key = %q, want %q", key, got[key], mk)
		}
		delete(got, key)
	}
	for key, mk := range got {
		t.Errorf("%s is marked marketplace-issuable as %q with no registry row seeded for it", key, mk)
	}
}

// MarketplaceKey must refuse the identity attributes the marketplace does not
// price. Reserving one fails the whole authorization as an unknown attribute,
// so "not issuable" has to be distinguishable from "issuable under its own name".
func TestMarketplaceKeyRefusesUnpricedIdentityFields(t *testing.T) {
	for _, key := range []string{"document_number", "issuing_state", "picture_id", "sex"} {
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
		"place_of_birth", "personal_number", "given_name_id", "family_name_id", "picture_id",
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
