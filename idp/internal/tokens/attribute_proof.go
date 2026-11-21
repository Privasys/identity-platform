// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tokens

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/golang-jwt/jwt/v5"
)

// The Privasys Attribute Verifier checks the evidence behind a wallet
// attribute (a provider's signed ID token, a mail code it sent, a card
// check) and signs a proof. At sign-in the wallet asks it for a disclosure
// of one proof, addressed to the relying party, and hands it over with the
// attributes. This server does not re-validate the evidence: it trusts the
// verifier's signature, as it trusts the Identity Verifier's.
//
// The verifier's public keys are pinned in configuration, read from the
// verifier over its attested channel when it is deployed. Its signing key
// lives on its sealed volume and survives upgrades, so the pin changes only
// if that volume is ever replaced.

// AttributeDisclosureVCT is the SD-JWT VC type of a verifier disclosure.
const AttributeDisclosureVCT = "https://privasys.org/vct/attribute-disclosure"

var attributeVerifierKeys atomic.Pointer[map[string]*ecdsa.PublicKey]

// SetAttributeVerifierJWKS pins the verifier's keys from a JWKS document.
// An empty document unpins them: no disclosure then proves anything.
func SetAttributeVerifierJWKS(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		attributeVerifierKeys.Store(nil)
		return nil
	}
	var set struct {
		Keys []struct {
			Kty, Crv, X, Y, Kid string
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &set); err != nil {
		return fmt.Errorf("attribute verifier JWKS: %w", err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			return errors.New("attribute verifier JWKS: keys must be EC P-256 with a kid")
		}
		pub, err := ecPublicFromJWK(k.X, k.Y)
		if err != nil {
			return fmt.Errorf("attribute verifier JWKS: %w", err)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("attribute verifier JWKS: no keys")
	}
	attributeVerifierKeys.Store(&keys)
	return nil
}

func ecPublicFromJWK(x, y string) (*ecdsa.PublicKey, error) {
	xb, err1 := base64.RawURLEncoding.DecodeString(x)
	yb, err2 := base64.RawURLEncoding.DecodeString(y)
	if err1 != nil || err2 != nil || len(xb) != 32 || len(yb) != 32 {
		return nil, errors.New("malformed EC key")
	}
	raw := append([]byte{4}, append(xb, yb...)...)
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, errors.New("the point is not on P-256")
	}
	_ = pub
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
}

// AttributeDisclosureProves reports whether disclosure is a live verifier
// disclosure, addressed to audience, that proves claim has value. Only the
// "proven" method counts: an "observed" value (what a provider's API said,
// unsigned) is shown to the holder but does not make an address verified.
func AttributeDisclosureProves(disclosure, audience, claim, value string) bool {
	keys := attributeVerifierKeys.Load()
	if keys == nil || disclosure == "" || audience == "" || value == "" {
		return false
	}
	// An SD-JWT: the issuer JWS, then "~"-separated disclosures (none here).
	jws, _, _ := strings.Cut(disclosure, "~")
	parsed, err := jwt.Parse(jws, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		pub, ok := (*keys)[kid]
		if !ok {
			return nil, errors.New("unknown attribute verifier key")
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		return false
	}
	if typ, _ := parsed.Header["typ"].(string); typ != "dc+sd-jwt" {
		return false
	}
	c, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	vct, _ := c["vct"].(string)
	got, _ := c["claim"].(string)
	method, _ := c["method"].(string)
	v, _ := c["value"].(string)
	return vct == AttributeDisclosureVCT && got == claim && method == "proven" && strings.EqualFold(v, value)
}
