// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package attributes loads the canonical attribute definitions from the shared
// JSON file (shared/canonical-attributes.json). The file is copied into this
// package directory for Go's embed directive (which doesn't support .. paths).
// Run `go generate ./...` after modifying the shared file.
//
// The copy silently went eleven attributes stale once already, so
// TestEmbeddedCopyMatchesShared byte-compares it against the shared original on
// every `go test`. Forgetting the generate step is a build failure, not a
// production surprise.
package attributes

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

//go:generate cp ../../../shared/canonical-attributes.json canonical-attributes.json

// Copies the CONTENTS: `cp -r src dst` nests src inside dst once dst exists, so
// the plain form silently built referential/referential/ on every re-run.
//go:generate cp -r ../../../shared/referential/. referential/

//go:embed canonical-attributes.json
var rawJSON []byte

// referentialFS holds the enumerated value sets (locale.json, ...) referenced by
// attribute valuesUrl. Served verbatim by the IdP at /referential/<name>.json so
// the wallet/SDK fetch the single source instead of bundling their own copy.
//
//go:embed referential
var referentialFS embed.FS

// Attribute describes a single canonical user attribute.
type Attribute struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Scope        string  `json:"scope"`
	ProfileField *string `json:"profileField"` // nil when not mapped to a top-level profile field
	Verifiable   bool    `json:"verifiable"`
	// ValuesURL, when set, points to the enumerated value set that constrains
	// this attribute (e.g. "/referential/locale.json"). Relative to the issuer.
	ValuesURL string `json:"valuesUrl,omitempty"`
	// DeviceSourced marks an attribute the client OS can supply directly (e.g.
	// locale from the device language). Such attributes are auto-filled by the
	// wallet and need not be prompted for.
	DeviceSourced bool `json:"deviceSourced,omitempty"`
	// IdentityVerifiable marks an attribute that can reach 'gov' assurance via
	// the identity-verifier enclave (passport/ID + biometric). Carried under the
	// request-gated 'identity' scope (see the identity-verifier (KYC) design).
	IdentityVerifiable bool `json:"identityVerifiable,omitempty"`
	// MultiValued marks an attribute the wallet may hold more than once (several
	// emails). Only the wallet acts on it — on import a differing value is added
	// alongside rather than flagged as a conflict — but it is decoded here so the
	// served referential and this struct describe the same document.
	MultiValued bool `json:"multiValued,omitempty"`
	// Assurance is this key's own level in the registry's vocabulary. Empty means
	// GovVerified for an identity-scope key and SelfAsserted otherwise; the
	// referential still states it on every identity key so a future gov attribute
	// outside that scope cannot arrive silently under-assured. Read it through
	// AssuranceLevel, never directly.
	Assurance string `json:"assurance,omitempty"`
	// GovKey names the government-backed twin of a self-asserted key
	// (given_name -> given_name_id). It is the whole of the pairing convention:
	// adding a pair is a twin key plus this pointer.
	GovKey string `json:"govKey,omitempty"`
	// SupersededBy names the spelling that replaces a genuinely retired key. It
	// is a hint to pickers and new integrators, never a redirect: the old key
	// keeps working verbatim, because a registration, a stored share link and a
	// signed voucher all name it. No key carries it — the two that did became
	// pairs instead, which is the better answer whenever both readings still mean
	// something.
	SupersededBy string `json:"supersededBy,omitempty"`
	// RequestOnly keeps a key out of every scope-derived set: the relying party
	// must name it, in its required_attributes whitelist (within the scope that
	// would have carried it) or in the per-request `attributes` parameter. It is
	// the fail-closed half of the model and is set on every '_id' key and every
	// priced key, so a client that asks for `identity` and nothing else
	// never acquires a billable disclosure it did not name.
	RequestOnly bool `json:"requestOnly,omitempty"`
	// CertifiedField is the identity-verifier field prove_field opens for this
	// key, when it differs from the key. The wallet's storage spelling
	// (given_name_id) is not a field the enclave certified, and asking for it by
	// that name is rejected as uncertified.
	CertifiedField string `json:"certifiedField,omitempty"`
	// Disclosure is "token" (the default for a gov key: an enclave-signed SD-JWT
	// VC from commit-and-prove) or "raw" where the enclave deliberately will not
	// re-certify the value (the DG2 portrait). A raw key is never billable.
	Disclosure string `json:"disclosure,omitempty"`
	// Derived marks a key with no stored value: the enclave computes it from the
	// identity receipt at disclosure time (document_valid, age_band). Its absence
	// from a profile is not a missing attribute.
	Derived bool `json:"derived,omitempty"`
	// Marketplace is set only for attributes the marketplace can issue as a paid
	// disclosure. Nil means free: a profile field, or an identity field the
	// verifier returns alongside a priced insight without pricing separately.
	Marketplace *Marketplace `json:"marketplace,omitempty"`
}

// Assurance vocabulary. These repeat the registry's own values (the `assurance`
// column of the `attributes` table), not the none/provider/gov ladder, because
// they are compared against what the control plane returns.
const (
	SelfAsserted = "self_asserted"
	GovVerified  = "gov_verified"
)

// Marketplace is the registry-facing half of an attribute: how the marketplace
// spells it and whether it charges. Price is deliberately absent — the registry
// (management-service migrations 055/056) owns it and may reprice at any time.
type Marketplace struct {
	// Key is the '<namespace>:<name>' form. A reservation resolves attributes by
	// namespace and refuses a bare name, and a billing grant must name the same
	// spelling or `covers` rejects it, so this is not cosmetic. It is not
	// "privasys:"+Key of the attribute either: the registry names the field the
	// ENCLAVE meters, so given_name_id is sold as privasys:given_name.
	Key string `json:"key"`
	// Billable reports whether a disclosure carries a charge at all.
	Billable bool `json:"billable"`
}

// ValueOption is one entry in an enumerated attribute's value set.
type ValueOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// ProviderDef describes how a single external identity provider maps its
// raw claim keys to our canonical attribute keys.
type ProviderDef struct {
	// ClaimMap maps provider-specific claim key → canonical attribute key.
	// Multiple provider keys may map to the same canonical key (first non-empty wins).
	ClaimMap map[string]string `json:"claimMap"`

	// IDClaim is the raw claim key that holds the provider's unique user ID
	// (e.g. "sub" for Google/LinkedIn, "id" for GitHub/Microsoft).
	IDClaim string `json:"idClaim"`

	// VerificationClaims maps canonical attribute key → the raw claim key
	// that indicates verification status. The special value "_always_verified"
	// means the provider only returns verified values for that attribute.
	VerificationClaims map[string]string `json:"verificationClaims"`
}

var (
	// All is the ordered list of all canonical attributes.
	All []Attribute

	// ByKey maps attribute key → definition.
	ByKey map[string]Attribute

	// ByScope maps scope → list of attribute keys in that scope.
	ByScope map[string][]string

	// Keys is the set of all canonical attribute keys.
	Keys map[string]bool

	// Providers maps provider name → claim mapping definitions.
	Providers map[string]ProviderDef

	// localeByLower maps a lowercased BCP-47 tag → its canonical form, built
	// from referential/locale.json. Used by NormalizeLocale.
	localeByLower map[string]string
)

func init() {
	var doc struct {
		Attributes []Attribute            `json:"attributes"`
		Providers  map[string]ProviderDef `json:"providers"`
	}
	if err := json.Unmarshal(rawJSON, &doc); err != nil {
		log.Fatalf("attributes: failed to parse canonical-attributes.json: %v", err)
	}

	All = doc.Attributes
	ByKey = make(map[string]Attribute, len(All))
	ByScope = make(map[string][]string)
	Keys = make(map[string]bool, len(All))

	for _, a := range All {
		ByKey[a.Key] = a
		Keys[a.Key] = true
		ByScope[a.Scope] = append(ByScope[a.Scope], a.Key)
	}

	Providers = doc.Providers

	localeByLower = map[string]string{}
	for _, v := range ValueSet("locale") {
		localeByLower[strings.ToLower(v.Value)] = v.Value
	}
}

// AssuranceLevel is the attribute's own assurance in the registry's vocabulary.
//
// The referential states it explicitly on every gov key; the fallback exists so
// an older copy of the document, which had no field at all, still reads the
// identity scope as government-backed rather than silently self-asserted.
func (a Attribute) AssuranceLevel() string {
	if a.Assurance != "" {
		return a.Assurance
	}
	if a.Scope == "identity" {
		// Only the identity-verifier enclave can put a value in the identity
		// scope, so there is no self-asserted reading of one.
		return GovVerified
	}
	return SelfAsserted
}

// IsGovVerified reports whether disclosing this key means disclosing something a
// government document evidenced.
func (a Attribute) IsGovVerified() bool { return a.AssuranceLevel() == GovVerified }

// CertifiedFieldName is the identity-verifier field prove_field opens for this
// key. It differs from the key exactly where a gov key carries an '_id' suffix
// the enclave never saw: the passport commitment is 'given_name', and asking for
// 'given_name_id' is rejected as an uncertified field.
func (a Attribute) CertifiedFieldName() string {
	if a.CertifiedField != "" {
		return a.CertifiedField
	}
	return a.Key
}

// InScope reports whether a scope-derived attribute set contains this key.
//
// Request-only keys are excluded by construction: they are reachable only when
// the relying party names them, which is the per-attribute request path (see
// requestedAttributes in the oidc package). The substring test on the scope
// string is the historical behaviour of /authorize, kept verbatim so the
// requested set and the filter that trims the wallet's answer never disagree.
func (a Attribute) InScope(scope string) bool {
	return !a.RequestOnly && a.Scope != "" && strings.Contains(scope, a.Scope)
}

// MarketplaceKey returns the namespaced key the marketplace prices a canonical
// attribute under, and whether it is issuable there at all.
//
// Callers must not synthesise "privasys:"+key instead, for two separate reasons.
// The identity scope carries document fields (document_number, place_of_birth,
// ...) that the verifier returns alongside a priced insight but that have no
// registry row, and naming one in a reservation fails the whole request as an
// unknown attribute. And an '_id' key is sold under the field the ENCLAVE
// meters, so given_name_id reserves privasys:given_name, not privasys:
// given_name_id, which nothing has ever seeded.
func MarketplaceKey(key string) (string, bool) {
	a, ok := ByKey[key]
	if !ok || a.Marketplace == nil || a.Marketplace.Key == "" || !a.Marketplace.Billable {
		return "", false
	}
	return a.Marketplace.Key, true
}

// ReferentialFile returns the raw bytes of an enumerated value set served at
// /referential/<name>.json (e.g. name="locale"). The IdP serves these verbatim
// so the wallet/SDK fetch the single source instead of bundling their own copy.
func ReferentialFile(name string) ([]byte, bool) {
	// The canonical attribute referential itself is servable too, so clients
	// (the portal's relying-party registration, SDKs) can build attribute
	// pickers from the single source instead of bundling a copy.
	if name == "canonical-attributes" {
		return rawJSON, true
	}
	b, err := referentialFS.ReadFile("referential/" + name + ".json")
	if err != nil {
		return nil, false
	}
	return b, true
}

// ValueSet parses and returns the enumerated values for an attribute (e.g.
// "locale"). Returns nil if there is no such value set.
func ValueSet(name string) []ValueOption {
	b, ok := ReferentialFile(name)
	if !ok {
		return nil
	}
	var doc struct {
		Values []ValueOption `json:"values"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		log.Printf("attributes: failed to parse referential/%s.json: %v", name, err)
		return nil
	}
	return doc.Values
}

// NormalizeLocale maps a raw locale string to a canonical BCP-47 tag from the
// locale value set (handles `_` separators and casing, e.g. en_US -> en-US;
// falls back to the base language tag, else returns the cleaned input).
func NormalizeLocale(raw string) string {
	if raw == "" {
		return raw
	}
	cleaned := strings.ReplaceAll(strings.TrimSpace(raw), "_", "-")
	if canon, ok := localeByLower[strings.ToLower(cleaned)]; ok {
		return canon
	}
	base := strings.SplitN(strings.ToLower(cleaned), "-", 2)[0]
	if canon, ok := localeByLower[base]; ok {
		return canon
	}
	return cleaned
}

// NormalizeClaims converts raw provider claims to canonical attribute key/value
// pairs using the shared provider claim map. Returns the canonical attributes
// and the provider's unique user ID. If the provider is unknown, passes through
// any keys that match canonical attribute names.
func NormalizeClaims(provider string, raw map[string]interface{}) (attrs map[string]string, userID string) {
	attrs = make(map[string]string)

	prov, ok := Providers[provider]
	if !ok {
		// Unknown provider — passthrough canonical keys.
		for k, v := range raw {
			if s, ok := v.(string); ok && s != "" && Keys[k] {
				attrs[k] = s
			}
		}
		// Try common ID fields.
		for _, k := range []string{"sub", "id", "user_id"} {
			if v, ok := raw[k]; ok {
				userID = fmt.Sprintf("%v", v)
				break
			}
		}
		return
	}

	// Extract user ID from the provider-specific claim.
	if v, ok := raw[prov.IDClaim]; ok {
		userID = fmt.Sprintf("%v", v)
	}

	// Map provider claims to canonical keys.
	for providerKey, canonicalKey := range prov.ClaimMap {
		if canonicalKey == "sub" {
			continue // user ID handled separately
		}
		if attrs[canonicalKey] != "" {
			continue // first non-empty wins
		}
		if v, ok := raw[providerKey]; ok {
			if s, ok := v.(string); ok && s != "" {
				attrs[canonicalKey] = s
			}
		}
	}

	// Normalise enumerated values to their canonical form.
	if loc := attrs["locale"]; loc != "" {
		attrs["locale"] = NormalizeLocale(loc)
	}

	return
}
