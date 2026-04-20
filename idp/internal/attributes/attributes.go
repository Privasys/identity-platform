// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package attributes loads the canonical attribute definitions from the shared
// JSON file (shared/canonical-attributes.json). The file is copied into this
// package directory for Go's embed directive (which doesn't support .. paths).
// Run `go generate ./...` after modifying the shared file.
package attributes

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
)

//go:generate cp ../../../shared/canonical-attributes.json canonical-attributes.json

//go:embed canonical-attributes.json
var rawJSON []byte

// Attribute describes a single canonical user attribute.
type Attribute struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	Scope        string  `json:"scope"`
	ProfileField *string `json:"profileField"` // nil when not mapped to a top-level profile field
	Verifiable   bool    `json:"verifiable"`
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

	return
}
