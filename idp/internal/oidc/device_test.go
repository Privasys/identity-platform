// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// RFC 7636 PKCE test vector (also used in TestPKCE).
const (
	testPKCEVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func newDeviceTestEnv(t *testing.T) (*clients.Registry, *store.DB, *tokens.Issuer) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "idp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	iss, err := tokens.NewIssuer(filepath.Join(dir, "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	reg := clients.NewRegistry(db)
	if _, err := reg.RegisterWithID("privasys-cli", "Privasys CLI",
		[]string{"https://privasys.id/device"}, "", nil); err != nil {
		t.Fatalf("register client: %v", err)
	}
	return reg, db, iss
}

func postForm(t *testing.T, h http.HandlerFunc, path string, form url.Values) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	return rec.Code, body
}

// simulateWalletApproval reproduces what the FIDO2 completion handler does:
// it mints the authorization code from the AuthSession and marks the session
// authenticated. This is the same path the wallet drives over the relay.
// The user row must already exist (FIDO2 registration creates it in the real
// flow); refresh_tokens has a foreign key to users.
func simulateWalletApproval(t *testing.T, db *store.DB, codes *CodeStore, sessions *SessionStore, deviceCode string, devices *DeviceStore, userID string) {
	t.Helper()
	if _, err := db.Exec("INSERT OR IGNORE INTO users (user_id) VALUES (?)", userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	da, _ := devices.GetByDeviceCode(deviceCode)
	session, _ := sessions.Get(da.SessionID)
	authCode := codes.Create(&AuthCode{
		ClientID:            session.ClientID,
		RedirectURI:         session.RedirectURI,
		UserID:              userID,
		Scope:               session.Scope,
		Nonce:               session.Nonce,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: session.CodeChallengeMethod,
		AuthTime:            time.Now(),
	})
	sessions.Complete(da.SessionID, userID, authCode)
}

func TestDeviceFlowEndToEnd(t *testing.T) {
	reg, db, iss := newDeviceTestEnv(t)
	codes := NewCodeStore()
	sessions := NewSessionStore()
	devices := NewDeviceStore()

	devHandler := HandleDeviceAuthorization(reg, sessions, devices, "https://privasys.id")
	tokenHandler := HandleToken(reg, codes, devices, sessions, iss, db, nil)

	// 1. Begin device authorization.
	code, body := postForm(t, devHandler, "/device_authorization", url.Values{
		"client_id":      {"privasys-cli"},
		"scope":          {"openid email profile offline_access"},
		"code_challenge": {testPKCEChallenge},
		"agent_name":     {"Claude Code"},
	})
	if code != http.StatusOK {
		t.Fatalf("device_authorization: expected 200, got %d (%v)", code, body)
	}
	deviceCode, _ := body["device_code"].(string)
	userCode, _ := body["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("missing device_code/user_code in %v", body)
	}
	if !strings.Contains(userCode, "-") {
		t.Errorf("user_code should be grouped (XXXX-XXXX), got %q", userCode)
	}
	if vc, _ := body["verification_uri"].(string); vc != "https://privasys.id/device" {
		t.Errorf("verification_uri = %q", vc)
	}
	if qr, _ := body["qr_payload"].(string); !strings.HasPrefix(qr, "https://privasys.id/scp?p=") {
		t.Errorf("qr_payload = %q", qr)
	}

	// Disable poll rate-limiting for the rest of the test.
	da, _ := devices.GetByDeviceCode(deviceCode)
	da.Interval = 0

	poll := func() (int, map[string]interface{}) {
		return postForm(t, tokenHandler, "/token", url.Values{
			"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code":   {deviceCode},
			"client_id":     {"privasys-cli"},
			"code_verifier": {testPKCEVerifier},
		})
	}

	// 2. Poll before approval -> authorization_pending.
	c, b := poll()
	if c != http.StatusBadRequest || b["error"] != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %d %v", c, b)
	}

	// 3. Wallet approves.
	simulateWalletApproval(t, db, codes, sessions, deviceCode, devices, "user-xyz")

	// 4. Poll after approval -> tokens.
	c, b = poll()
	if c != http.StatusOK {
		t.Fatalf("expected 200 with tokens, got %d %v", c, b)
	}
	if _, ok := b["access_token"].(string); !ok {
		t.Errorf("missing access_token in %v", b)
	}
	if _, ok := b["id_token"].(string); !ok {
		t.Errorf("missing id_token in %v", b)
	}
	if _, ok := b["refresh_token"].(string); !ok {
		t.Errorf("offline_access requested but no refresh_token in %v", b)
	}

	// 5. Replay the device_code -> expired_token (single-use).
	c, b = poll()
	if c != http.StatusBadRequest || b["error"] != "expired_token" {
		t.Fatalf("expected expired_token on replay, got %d %v", c, b)
	}
}

func TestDeviceFlowPKCEMismatch(t *testing.T) {
	reg, db, iss := newDeviceTestEnv(t)
	codes := NewCodeStore()
	sessions := NewSessionStore()
	devices := NewDeviceStore()
	devHandler := HandleDeviceAuthorization(reg, sessions, devices, "https://privasys.id")
	tokenHandler := HandleToken(reg, codes, devices, sessions, iss, db, nil)

	_, body := postForm(t, devHandler, "/device_authorization", url.Values{
		"client_id":      {"privasys-cli"},
		"scope":          {"openid"},
		"code_challenge": {testPKCEChallenge},
	})
	deviceCode := body["device_code"].(string)
	da, _ := devices.GetByDeviceCode(deviceCode)
	da.Interval = 0
	simulateWalletApproval(t, db, codes, sessions, deviceCode, devices, "user-xyz")

	c, b := postForm(t, tokenHandler, "/token", url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {"privasys-cli"},
		"code_verifier": {"the-wrong-verifier"},
	})
	if c != http.StatusBadRequest || b["error"] != "invalid_grant" {
		t.Fatalf("expected invalid_grant for bad PKCE, got %d %v", c, b)
	}
}

func TestDeviceFlowDenied(t *testing.T) {
	reg, db, iss := newDeviceTestEnv(t)
	codes := NewCodeStore()
	sessions := NewSessionStore()
	devices := NewDeviceStore()
	devHandler := HandleDeviceAuthorization(reg, sessions, devices, "https://privasys.id")
	tokenHandler := HandleToken(reg, codes, devices, sessions, iss, db, nil)

	_, body := postForm(t, devHandler, "/device_authorization", url.Values{
		"client_id":      {"privasys-cli"},
		"scope":          {"openid"},
		"code_challenge": {testPKCEChallenge},
	})
	deviceCode := body["device_code"].(string)
	userCode := body["user_code"].(string)
	da, _ := devices.GetByDeviceCode(deviceCode)
	da.Interval = 0

	if !devices.Deny(userCode) {
		t.Fatal("Deny returned false")
	}

	c, b := postForm(t, tokenHandler, "/token", url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {"privasys-cli"},
		"code_verifier": {testPKCEVerifier},
	})
	if c != http.StatusBadRequest || b["error"] != "access_denied" {
		t.Fatalf("expected access_denied, got %d %v", c, b)
	}
}

func TestDeviceAuthorizationValidation(t *testing.T) {
	reg, _, _ := newDeviceTestEnv(t)
	sessions := NewSessionStore()
	devices := NewDeviceStore()
	devHandler := HandleDeviceAuthorization(reg, sessions, devices, "https://privasys.id")

	// Unknown client.
	c, b := postForm(t, devHandler, "/device_authorization", url.Values{
		"client_id":      {"nope"},
		"code_challenge": {testPKCEChallenge},
	})
	if c != http.StatusBadRequest || b["error"] != "invalid_client" {
		t.Errorf("unknown client: got %d %v", c, b)
	}

	// Missing PKCE challenge.
	c, b = postForm(t, devHandler, "/device_authorization", url.Values{
		"client_id": {"privasys-cli"},
	})
	if c != http.StatusBadRequest || b["error"] != "invalid_request" {
		t.Errorf("missing code_challenge: got %d %v", c, b)
	}
}

func TestDeviceCodeSlowDown(t *testing.T) {
	reg, db, iss := newDeviceTestEnv(t)
	codes := NewCodeStore()
	sessions := NewSessionStore()
	devices := NewDeviceStore()
	devHandler := HandleDeviceAuthorization(reg, sessions, devices, "https://privasys.id")
	tokenHandler := HandleToken(reg, codes, devices, sessions, iss, db, nil)

	_, body := postForm(t, devHandler, "/device_authorization", url.Values{
		"client_id":      {"privasys-cli"},
		"scope":          {"openid"},
		"code_challenge": {testPKCEChallenge},
	})
	deviceCode := body["device_code"].(string)

	poll := func() (int, map[string]interface{}) {
		return postForm(t, tokenHandler, "/token", url.Values{
			"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code":   {deviceCode},
			"client_id":     {"privasys-cli"},
			"code_verifier": {testPKCEVerifier},
		})
	}

	// First poll: allowed (pending). Second immediate poll: slow_down.
	if c, b := poll(); c != http.StatusBadRequest || b["error"] != "authorization_pending" {
		t.Fatalf("first poll: got %d %v", c, b)
	}
	if c, b := poll(); c != http.StatusBadRequest || b["error"] != "slow_down" {
		t.Fatalf("second immediate poll: expected slow_down, got %d %v", c, b)
	}
}

func TestUserCodeFormatAndNormalize(t *testing.T) {
	uc := generateUserCode()
	if len(uc) != userCodeLen {
		t.Fatalf("user code length = %d, want %d", len(uc), userCodeLen)
	}
	for _, r := range uc {
		if !strings.ContainsRune(userCodeAlphabet, r) {
			t.Errorf("user code %q contains out-of-alphabet rune %q", uc, r)
		}
	}
	display := formatUserCode(uc)
	if normalizeUserCode(display) != uc {
		t.Errorf("normalize(format(%q)) = %q, want %q", uc, normalizeUserCode(display), uc)
	}
	if normalizeUserCode("  ab-cd ef ") != "ABCDEF" {
		t.Errorf("normalizeUserCode failed: %q", normalizeUserCode("  ab-cd ef "))
	}
}

func TestSanitizeAgentName(t *testing.T) {
	if got := sanitizeAgentName("  Claude\tCode\n "); got != "ClaudeCode" {
		t.Errorf("control chars not stripped: %q", got)
	}
	long := strings.Repeat("x", 200)
	if got := sanitizeAgentName(long); len(got) > maxAgentNameLen {
		t.Errorf("agent name not capped: len=%d", len(got))
	}
	if got := sanitizeAgentName(""); got != "" {
		t.Errorf("empty should stay empty, got %q", got)
	}
}
