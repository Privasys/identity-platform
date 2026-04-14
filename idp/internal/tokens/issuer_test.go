// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tokens

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssuerAutoGenerate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")

	iss, err := NewIssuer(keyPath, "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	// Key file should have been created.
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("expected key file to be created")
	}

	// Reload should work with the same key.
	iss2, err := NewIssuer(keyPath, "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer (reload): %v", err)
	}
	if iss.keyID != iss2.keyID {
		t.Error("expected same key ID after reload")
	}
}

func TestIssueAndVerifyIDToken(t *testing.T) {
	dir := t.TempDir()
	iss, err := NewIssuer(filepath.Join(dir, "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	token, err := iss.IssueIDToken(IDTokenClaims{
		Subject:          "user-123",
		Email:            "alice@privasys.org",
		Name:             "Alice",
		AttestationLevel: "verified",
		Audience:         "test-client",
		Nonce:            "nonce-abc",
		AuthTime:         time.Now(),
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Verify the token.
	claims, err := iss.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	if sub, _ := claims["sub"].(string); sub != "user-123" {
		t.Errorf("sub: expected user-123, got %s", sub)
	}
	if email, _ := claims["email"].(string); email != "alice@privasys.org" {
		t.Errorf("email: expected alice@privasys.org, got %s", email)
	}
	if level, _ := claims["attestation_level"].(string); level != "verified" {
		t.Errorf("attestation_level: expected verified, got %s", level)
	}
}

func TestIssueAccessToken(t *testing.T) {
	dir := t.TempDir()
	iss, err := NewIssuer(filepath.Join(dir, "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	token, err := iss.IssueAccessToken("user-456", "client-xyz", nil)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	claims, err := iss.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	if sub := claims["sub"].(string); sub != "user-456" {
		t.Errorf("sub: expected user-456, got %s", sub)
	}
	if aud := claims["aud"].(string); aud != "client-xyz" {
		t.Errorf("aud: expected client-xyz, got %s", aud)
	}
}

func TestJWKS(t *testing.T) {
	dir := t.TempDir()
	iss, err := NewIssuer(filepath.Join(dir, "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	req := httptest.NewRequest("GET", "/jwks", nil)
	rec := httptest.NewRecorder()
	iss.HandleJWKS(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var jwks map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok || len(keys) != 1 {
		t.Fatalf("expected 1 key, got %v", jwks)
	}

	key := keys[0].(map[string]interface{})
	if key["kty"] != "EC" {
		t.Errorf("kty: expected EC, got %v", key["kty"])
	}
	if key["crv"] != "P-256" {
		t.Errorf("crv: expected P-256, got %v", key["crv"])
	}
	if key["alg"] != "ES256" {
		t.Errorf("alg: expected ES256, got %v", key["alg"])
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	dir := t.TempDir()
	iss, err := NewIssuer(filepath.Join(dir, "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	// Create a token that's already expired.
	claims := map[string]interface{}{
		"iss": "https://privasys.id",
		"sub": "user-expired",
		"aud": "test",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}
	token, err := iss.sign(claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = iss.VerifyAccessToken(token)
	if err == nil {
		t.Fatal("expected expired token to fail verification")
	}
}
