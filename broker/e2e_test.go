// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package main_test contains an end-to-end test that simulates the mobile
// app → broker → attestation-server token flow.
//
// This catches integration issues (mismatched claims, broken JWKS, wrong
// audience/role format) without needing a real mobile device or deployed
// services.
package main_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/auth-broker/internal/appattest"
	"github.com/Privasys/auth-broker/internal/tokens"
)

// TestE2E_AppAttest_To_AttestationServer simulates the full flow:
//
//  1. Mobile app calls GET /app-challenge → receives a challenge
//  2. Mobile app calls POST /app-token with a (simulated) attestation → receives a JWT
//  3. The JWT's signature is verified against the broker's /jwks endpoint
//  4. The JWT's claims (iss, aud, roles, exp) are validated exactly as the
//     attestation server would validate them
//  5. The AS's OIDC discovery endpoint is hit to find the JWKS URI
//
// This validates the entire chain without needing a real Apple/Google
// attestation or a deployed attestation server.
func TestE2E_AppAttest_To_AttestationServer(t *testing.T) {
	// ── Setup: generate EC P-256 key and start broker test server ────

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	ecDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecDER,
	})

	// We need the server URL before creating the issuer (for the iss claim),
	// but need the issuer before starting the server. Solve with a handler
	// wrapper that gets set after both are ready.
	var handler http.Handler
	brokerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	defer brokerServer.Close()

	brokerURL := brokerServer.URL

	issuer, err := tokens.NewIssuer(tokens.Config{
		PrivateKeyPEM: string(privKeyPEM),
		IssuerURL:     brokerURL,
		Audience:      "privasys-platform",
		Role:          "attestation-server:client",
	})
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}

	attHandler := appattest.New(appattest.Config{
		Issuer:     issuer,
		TeamID:     "TESTTEAM",
		BundleID:   "org.privasys.wallet",
		Production: false,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /app-token", attHandler.HandleAppToken)
	mux.HandleFunc("GET /app-challenge", attHandler.HandleChallenge)
	mux.HandleFunc("GET /.well-known/openid-configuration", issuer.HandleOIDCDiscovery)
	mux.HandleFunc("GET /jwks", issuer.HandleJWKS)

	handler = mux
	t.Logf("broker test server: %s", brokerURL)

	// ── Step 1: GET /app-challenge ───────────────────────────────────

	t.Run("1_get_challenge", func(t *testing.T) {
		resp, err := http.Get(brokerURL + "/app-challenge")
		if err != nil {
			t.Fatalf("GET /app-challenge: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var body struct {
			Challenge string `json:"challenge"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode challenge: %v", err)
		}
		if body.Challenge == "" {
			t.Fatal("challenge is empty")
		}

		// Verify it's valid base64 and 32 bytes.
		decoded, err := base64.StdEncoding.DecodeString(body.Challenge)
		if err != nil {
			t.Fatalf("challenge is not valid base64: %v", err)
		}
		if len(decoded) != 32 {
			t.Fatalf("challenge should be 32 bytes, got %d", len(decoded))
		}
	})

	// ── Step 2: POST /app-token (simulated iOS attestation) ─────────

	var jwtToken string

	t.Run("2_exchange_token_ios", func(t *testing.T) {
		// Get a challenge first.
		challengeResp, err := http.Get(brokerURL + "/app-challenge")
		if err != nil {
			t.Fatalf("GET /app-challenge: %v", err)
		}
		var challBody struct {
			Challenge string `json:"challenge"`
		}
		json.NewDecoder(challengeResp.Body).Decode(&challBody)
		challengeResp.Body.Close()

		// Simulate a fake iOS attestation (>100 bytes).
		fakeAttestation := make([]byte, 256)
		rand.Read(fakeAttestation)

		payload := map[string]string{
			"platform":    "ios",
			"attestation": base64.StdEncoding.EncodeToString(fakeAttestation),
			"keyId":       "ABCDEF1234567890ABCDEF1234567890",
			"challenge":   challBody.Challenge,
		}
		payloadJSON, _ := json.Marshal(payload)

		resp, err := http.Post(brokerURL+"/app-token", "application/json", strings.NewReader(string(payloadJSON)))
		if err != nil {
			t.Fatalf("POST /app-token: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
		}

		var tokenResp struct {
			Token     string `json:"token"`
			ExpiresIn int    `json:"expires_in"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			t.Fatalf("decode token response: %v", err)
		}
		if tokenResp.Token == "" {
			t.Fatal("token is empty")
		}
		if tokenResp.ExpiresIn != 300 {
			t.Fatalf("expected expires_in=300, got %d", tokenResp.ExpiresIn)
		}

		jwtToken = tokenResp.Token
		t.Logf("received JWT: %s...%s", jwtToken[:20], jwtToken[len(jwtToken)-10:])
	})

	// ── Step 3: POST /app-token (Android) ────────────────────────────

	t.Run("2b_exchange_token_android", func(t *testing.T) {
		challengeResp, err := http.Get(brokerURL + "/app-challenge")
		if err != nil {
			t.Fatalf("GET /app-challenge: %v", err)
		}
		var challBody struct {
			Challenge string `json:"challenge"`
		}
		json.NewDecoder(challengeResp.Body).Decode(&challBody)
		challengeResp.Body.Close()

		payload := map[string]string{
			"platform":    "android",
			"attestation": "fake-play-integrity-token",
			"keyId":       "",
			"challenge":   challBody.Challenge,
		}
		payloadJSON, _ := json.Marshal(payload)

		resp, err := http.Post(brokerURL+"/app-token", "application/json", strings.NewReader(string(payloadJSON)))
		if err != nil {
			t.Fatalf("POST /app-token: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
		}

		var tokenResp struct {
			Token string `json:"token"`
		}
		json.NewDecoder(resp.Body).Decode(&tokenResp)
		if tokenResp.Token == "" {
			t.Fatal("android token is empty")
		}
	})

	// ── Step 3: OIDC Discovery ───────────────────────────────────────

	t.Run("3_oidc_discovery", func(t *testing.T) {
		resp, err := http.Get(brokerURL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("GET /.well-known/openid-configuration: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var disc struct {
			Issuer  string `json:"issuer"`
			JwksURI string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}
		if disc.Issuer != brokerURL {
			t.Fatalf("issuer mismatch: got %q, want %q", disc.Issuer, brokerURL)
		}
		if disc.JwksURI != brokerURL+"/jwks" {
			t.Fatalf("jwks_uri mismatch: got %q, want %q", disc.JwksURI, brokerURL+"/jwks")
		}
	})

	// ── Step 4: JWKS endpoint returns valid key ──────────────────────

	t.Run("4_jwks_endpoint", func(t *testing.T) {
		resp, err := http.Get(brokerURL + "/jwks")
		if err != nil {
			t.Fatalf("GET /jwks: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var jwks struct {
			Keys []struct {
				Kty string `json:"kty"`
				Kid string `json:"kid"`
				Alg string `json:"alg"`
				Crv string `json:"crv"`
				X   string `json:"x"`
				Y   string `json:"y"`
			} `json:"keys"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
			t.Fatalf("decode JWKS: %v", err)
		}
		if len(jwks.Keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
		}
		key := jwks.Keys[0]
		if key.Kty != "EC" {
			t.Fatalf("expected EC key, got %s", key.Kty)
		}
		if key.Alg != "ES256" {
			t.Fatalf("expected ES256, got %s", key.Alg)
		}
		if key.Crv != "P-256" {
			t.Fatalf("expected P-256, got %s", key.Crv)
		}
		if key.Kid == "" {
			t.Fatal("kid is empty")
		}
		if key.X == "" || key.Y == "" {
			t.Fatal("x or y is empty")
		}
	})

	// ── Step 5: Validate JWT exactly as the attestation server does ──

	t.Run("5_validate_jwt_as_attestation_server", func(t *testing.T) {
		if jwtToken == "" {
			t.Skip("no JWT from step 2")
		}

		// 5a. Decode header + claims without verification.
		parts := strings.SplitN(jwtToken, ".", 3)
		if len(parts) != 3 {
			t.Fatalf("JWT should have 3 parts, got %d", len(parts))
		}

		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("decode header: %v", err)
		}
		var header struct {
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			Typ string `json:"typ"`
		}
		if err := json.Unmarshal(headerJSON, &header); err != nil {
			t.Fatalf("parse header: %v", err)
		}

		if header.Alg != "ES256" {
			t.Fatalf("expected alg=ES256, got %s", header.Alg)
		}
		if header.Typ != "JWT" {
			t.Fatalf("expected typ=JWT, got %s", header.Typ)
		}
		if header.Kid == "" {
			t.Fatal("kid is empty in JWT header")
		}

		claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode claims: %v", err)
		}
		var claims map[string]interface{}
		if err := json.Unmarshal(claimsJSON, &claims); err != nil {
			t.Fatalf("parse claims: %v", err)
		}

		// 5b. Validate issuer.
		iss, _ := claims["iss"].(string)
		if iss != brokerURL {
			t.Fatalf("iss mismatch: got %q, want %q", iss, brokerURL)
		}

		// 5c. Validate audience — must match what AS expects.
		expectedAudience := "privasys-platform"
		aud, _ := claims["aud"].(string)
		if aud != expectedAudience {
			t.Fatalf("aud mismatch: got %q, want %q", aud, expectedAudience)
		}

		// 5d. Validate subject.
		sub, _ := claims["sub"].(string)
		if sub == "" {
			t.Fatal("sub is empty")
		}
		if !strings.HasPrefix(sub, "ios-wallet:") {
			t.Fatalf("expected sub to start with 'ios-wallet:', got %q", sub)
		}

		// 5e. Validate expiry (should be ~5 min from now).
		exp, ok := claims["exp"].(float64)
		if !ok {
			t.Fatal("exp claim missing or not a number")
		}
		expTime := time.Unix(int64(exp), 0)
		if time.Until(expTime) < 4*time.Minute || time.Until(expTime) > 6*time.Minute {
			t.Fatalf("exp should be ~5 min from now, got %v (delta: %v)", expTime, time.Until(expTime))
		}

		// 5f. Validate role claim — must match AS's expected format.
		// The AS checks both the configured claim and a "roles" array.
		expectedRole := "attestation-server:client"
		roles, ok := claims["roles"].([]interface{})
		if !ok {
			t.Fatal("'roles' claim missing or not an array")
		}
		foundRole := false
		for _, r := range roles {
			if s, ok := r.(string); ok && s == expectedRole {
				foundRole = true
				break
			}
		}
		if !foundRole {
			t.Fatalf("role %q not found in roles: %v", expectedRole, roles)
		}

		// 5g. Fetch JWKS and verify signature — this is what the AS does.
		// Discover JWKS URI via OIDC discovery.
		discResp, err := http.Get(iss + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("OIDC discovery: %v", err)
		}
		defer discResp.Body.Close()
		var disc struct {
			JwksURI string `json:"jwks_uri"`
		}
		json.NewDecoder(discResp.Body).Decode(&disc)

		// Fetch JWKS.
		jwksResp, err := http.Get(disc.JwksURI)
		if err != nil {
			t.Fatalf("fetch JWKS: %v", err)
		}
		defer jwksResp.Body.Close()

		var jwks struct {
			Keys []struct {
				Kid string `json:"kid"`
				X   string `json:"x"`
				Y   string `json:"y"`
			} `json:"keys"`
		}
		json.NewDecoder(jwksResp.Body).Decode(&jwks)

		// Find the key matching the JWT's kid.
		var xB64, yB64 string
		for _, k := range jwks.Keys {
			if k.Kid == header.Kid {
				xB64 = k.X
				yB64 = k.Y
				break
			}
		}
		if xB64 == "" {
			t.Fatalf("key %q not found in JWKS", header.Kid)
		}

		// Reconstruct the EC public key from JWKS.
		xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
		if err != nil {
			t.Fatalf("decode x: %v", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
		if err != nil {
			t.Fatalf("decode y: %v", err)
		}
		pubKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}

		// Verify ES256 signature.
		signingInput := []byte(parts[0] + "." + parts[1])
		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}

		// ES256: sig is r || s, each 32 bytes.
		if len(sigBytes) != 64 {
			t.Fatalf("expected 64-byte signature, got %d", len(sigBytes))
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])

		hash := sha256.Sum256(signingInput)
		if !ecdsa.Verify(pubKey, hash[:], r, s) {
			t.Fatal("ECDSA signature verification failed")
		}

		t.Log("JWT signature verified successfully via JWKS")
		t.Logf("claims: iss=%s aud=%s sub=%s roles=%v exp=%v", iss, aud, sub, roles, expTime)
	})

	// ── Step 6: Error cases ──────────────────────────────────────────

	t.Run("6a_invalid_platform", func(t *testing.T) {
		payload := `{"platform":"windows","attestation":"dGVzdA==","keyId":"test","challenge":"dGVzdA=="}`
		resp, err := http.Post(brokerURL+"/app-token", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("POST /app-token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})

	t.Run("6b_missing_attestation_ios", func(t *testing.T) {
		payload := `{"platform":"ios","attestation":"","keyId":"test","challenge":"dGVzdA=="}`
		resp, err := http.Post(brokerURL+"/app-token", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("POST /app-token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("6c_attestation_too_short", func(t *testing.T) {
		short := base64.StdEncoding.EncodeToString([]byte("too-short"))
		payload := fmt.Sprintf(`{"platform":"ios","attestation":"%s","keyId":"test","challenge":"dGVzdA=="}`, short)
		resp, err := http.Post(brokerURL+"/app-token", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("POST /app-token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("6d_invalid_json", func(t *testing.T) {
		resp, err := http.Post(brokerURL+"/app-token", "application/json", strings.NewReader("{invalid"))
		if err != nil {
			t.Fatalf("POST /app-token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})
}
