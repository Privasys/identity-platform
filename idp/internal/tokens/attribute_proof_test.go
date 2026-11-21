// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func disclosureFor(t *testing.T, key *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = "dc+sd-jwt"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s + "~"
}

func TestAttributeDisclosureProves(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","kid":"av1","x":"%s","y":"%s"}]}`,
		b64(key.X.FillBytes(make([]byte, 32))), b64(key.Y.FillBytes(make([]byte, 32))))
	if err := SetAttributeVerifierJWKS(jwks); err != nil {
		t.Fatal(err)
	}
	defer SetAttributeVerifierJWKS("")
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"aud": "rp-1", "vct": AttributeDisclosureVCT, "claim": "email",
			"value": "alice@example.com", "method": "proven", "exp": time.Now().Add(time.Minute).Unix()}
	}
	ok := disclosureFor(t, key, "av1", base())
	if !AttributeDisclosureProves(ok, "rp-1", "email", "Alice@Example.com") {
		t.Fatal("a valid disclosure did not prove the address")
	}
	for name, c := range map[string]func(jwt.MapClaims){
		"observed":      func(m jwt.MapClaims) { m["method"] = "observed" },
		"other address": func(m jwt.MapClaims) { m["value"] = "eve@example.com" },
		"other claim":   func(m jwt.MapClaims) { m["claim"] = "name" },
		"expired":       func(m jwt.MapClaims) { m["exp"] = time.Now().Add(-time.Minute).Unix() },
		"other vct":     func(m jwt.MapClaims) { m["vct"] = "https://privasys.org/vct/identity-disclosure" },
	} {
		m := base()
		c(m)
		if AttributeDisclosureProves(disclosureFor(t, key, "av1", m), "rp-1", "email", "alice@example.com") {
			t.Fatalf("%s: accepted", name)
		}
	}
	if AttributeDisclosureProves(ok, "rp-2", "email", "alice@example.com") {
		t.Fatal("a disclosure for another app was accepted")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if AttributeDisclosureProves(disclosureFor(t, other, "av1", base()), "rp-1", "email", "alice@example.com") {
		t.Fatal("a disclosure signed by another key was accepted")
	}
	SetAttributeVerifierJWKS("")
	if AttributeDisclosureProves(ok, "rp-1", "email", "alice@example.com") {
		t.Fatal("accepted with no pinned keys")
	}
}
