// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package attributes loads the canonical attribute definitions from the shared
// JSON file (shared/canonical-attributes.json). The file is copied into this
// package directory for Go's embed directive (which doesn't support .. paths).
// Run `go generate ./...` after modifying the shared file.
package attributes

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

//go:generate cp ../../../shared/canonical-attributes.json canonical-attributes.json
//go:generate cp -r ../../../shared/referential referential

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
	// request-gated 'identity' scope (see kyc-enclave-design.md §3).
	IdentityVerifiable bool `json:"identityVerifiable,omitempty"`
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

// ReferentialFile returns the raw bytes of an enumerated value set served at
// /referential/<name>.json (e.g. name="locale"). The IdP serves these verbatim
// so the wallet/SDK fetch the single source instead of bundling their own copy.
func ReferentialFile(name string) ([]byte, bool) {
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
