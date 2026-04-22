// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDiscovery(t *testing.T) {
	handler := HandleDiscovery("https://privasys.id")

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var doc map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	tests := []struct {
		field    string
		expected string
	}{
		{"issuer", "https://privasys.id"},
		{"authorization_endpoint", "https://privasys.id/authorize"},
		{"token_endpoint", "https://privasys.id/token"},
		{"userinfo_endpoint", "https://privasys.id/userinfo"},
		{"jwks_uri", "https://privasys.id/jwks"},
	}

	for _, tt := range tests {
		got, ok := doc[tt.field].(string)
		if !ok || got != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.field, tt.expected, got)
		}
	}

	// Check scopes.
	scopes, ok := doc["scopes_supported"].([]interface{})
	if !ok || len(scopes) < 3 {
		t.Errorf("expected at least 3 scopes, got %v", scopes)
	}

	// Check claims.
	claims, ok := doc["claims_supported"].([]interface{})
	if !ok || len(claims) < 5 {
		t.Errorf("expected at least 5 claims, got %v", claims)
	}
}

func TestCodeStoreCreateAndConsume(t *testing.T) {
	cs := NewCodeStore()

	ac := &AuthCode{
		ClientID:    "test-client",
		RedirectURI: "https://example.com/callback",
		UserID:      "user-123",
		Scope:       "openid profile",
	}

	code := cs.Create(ac)
	if code == "" {
		t.Fatal("expected non-empty code")
	}

	// Consume should work once.
	retrieved, ok := cs.Consume(code)
	if !ok {
		t.Fatal("expected to consume code")
	}
	if retrieved.UserID != "user-123" {
		t.Errorf("expected user-123, got %s", retrieved.UserID)
	}

	// Second consume should fail (single-use).
	_, ok = cs.Consume(code)
	if ok {
		t.Fatal("expected second consume to fail")
	}
}

func TestSessionStore(t *testing.T) {
	ss := NewSessionStore()

	session := &AuthSession{
		SessionID: "sess-123",
		ClientID:  "client-abc",
		State:     "state-xyz",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	ss.Create(session)

	// Get should work.
	got, ok := ss.Get("sess-123")
	if !ok {
		t.Fatal("expected to find session")
	}
	if got.ClientID != "client-abc" {
		t.Errorf("expected client-abc, got %s", got.ClientID)
	}

	// Complete should work.
	ss.Complete("sess-123", "user-456", "auth-code-789")
	got, _ = ss.Get("sess-123")
	if !got.Authenticated {
		t.Error("expected session to be authenticated")
	}
	if got.AuthCode != "auth-code-789" {
		t.Errorf("expected auth-code-789, got %s", got.AuthCode)
	}

	// Unknown session should fail.
	_, ok = ss.Get("nonexistent")
	if ok {
		t.Fatal("expected nonexistent session to not be found")
	}
}

func TestPKCE(t *testing.T) {
	// S256 test vector from RFC 7636.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if !verifyPKCE(challenge, verifier) {
		t.Error("expected PKCE verification to pass")
	}

	if verifyPKCE(challenge, "wrong-verifier") {
		t.Error("expected PKCE verification to fail with wrong verifier")
	}
}


// Verifies the strict role taxonomy: a token minted for audience X must
// only carry roles prefixed with "X:".  Regression coverage for the
// handleJWTBearerGrant / handleAuthorizationCodeGrant / refresh-token
// paths.
func TestFilterRolesByAudience(t *testing.T) {
roles := []string{
"platform:admin",             // legacy bare-prefix, must be dropped
"privasys-platform:admin",
"privasys-platform:manager",
"management-service:manager", // different audience, must be dropped
"admin",                      // bare, must be dropped
}

tests := []struct {
aud  string
want []string
}{
{"privasys-platform", []string{"privasys-platform:admin", "privasys-platform:manager"}},
{"management-service", []string{"management-service:manager"}},
{"platform", []string{"platform:admin"}},
{"nonexistent", nil},
{"", roles}, // empty audience acts as a passthrough (no filtering)
}

for _, tt := range tests {
t.Run(tt.aud, func(t *testing.T) {
got := filterRolesByAudience(append([]string(nil), roles...), tt.aud)
if len(got) != len(tt.want) {
t.Fatalf("aud=%q: got %v, want %v", tt.aud, got, tt.want)
}
for i := range got {
if got[i] != tt.want[i] {
t.Errorf("aud=%q: got[%d]=%q, want %q", tt.aud, i, got[i], tt.want[i])
}
}
})
}
}

func TestAudienceFromScope(t *testing.T) {
tests := []struct {
scope, fallback, want string
}{
{"openid profile", "privasys-platform", "privasys-platform"},
{"openid audience:management-service", "privasys-platform", "management-service"},
{"audience:privasys-platform openid", "x", "privasys-platform"},
{"audience:", "fallback", "fallback"}, // empty value falls back
{"", "privasys-platform", "privasys-platform"},
}
for _, tt := range tests {
if got := audienceFromScope(tt.scope, tt.fallback); got != tt.want {
t.Errorf("scope=%q: got %q, want %q", tt.scope, got, tt.want)
}
}
}
