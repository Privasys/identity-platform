// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package spend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// proof signs an app proof the way the app's spend library does (typ
// spend-proof+jwt, aud = the callee host, the published kid).
func (f *fixture) proof(t *testing.T, key *ecdsa.PrivateKey, mutate func(jwt.MapClaims, map[string]any)) string {
	t.Helper()
	claims := jwt.MapClaims{"aud": "idp.test", "iat": time.Now().Unix(), "jti": randomID()}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = jwkOf(&f.appKey.PublicKey).Kid
	tok.Header["typ"] = "spend-proof+jwt"
	if mutate != nil {
		mutate(claims, tok.Header)
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyAppProof(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	name, err := f.h.VerifyAppProof(ctx, f.appID, f.proof(t, f.appKey, nil))
	if err != nil || name != "Harness" {
		t.Fatalf("good proof: %q %v", name, err)
	}

	p := f.proof(t, f.appKey, nil)
	if _, err := f.h.VerifyAppProof(ctx, f.appID, p); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := f.h.VerifyAppProof(ctx, f.appID, p); err == nil {
		t.Fatal("a replayed proof verified")
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	refused := map[string]string{
		"signed by another key": f.proof(t, other, nil),
		"addressed elsewhere":   f.proof(t, f.appKey, func(c jwt.MapClaims, _ map[string]any) { c["aud"] = "drive.privasys.org" }),
		"stale":                 f.proof(t, f.appKey, func(c jwt.MapClaims, _ map[string]any) { c["iat"] = time.Now().Add(-10 * time.Minute).Unix() }),
		"not a proof":           f.proof(t, f.appKey, func(_ jwt.MapClaims, h map[string]any) { h["typ"] = AssertionTyp }),
		"no jti":                f.proof(t, f.appKey, func(c jwt.MapClaims, _ map[string]any) { delete(c, "jti") }),
	}
	for why, proof := range refused {
		if _, err := f.h.VerifyAppProof(ctx, f.appID, proof); err == nil {
			t.Errorf("%s: verified", why)
		}
	}
	if _, err := f.h.VerifyAppProof(ctx, "", f.proof(t, f.appKey, nil)); err == nil {
		t.Error("empty app id verified")
	}

	if f.h.HasConsent("user-1", f.appID) {
		t.Fatal("consent before any grant")
	}
	f.grant(t, "user-1", 1000)
	if !f.h.HasConsent("user-1", f.appID) {
		t.Fatal("no consent after grant")
	}
}
