// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package oidc

import (
	"net/http"
	"net/url"
	"testing"

	idpsessions "github.com/Privasys/idp/internal/sessions"
	"github.com/Privasys/idp/internal/tokens"
)

// A refresh refused for what it asks (another platform's audience, a scope
// the grant does not cover) leaves the sign-in usable: the refresh token is
// spent only when a request is accepted. A token presented by another client
// is still spent.
func TestARefusedRefreshKeepsTheSignIn(t *testing.T) {
	tokens.SetPlatformAudiences([]string{"privasys-platform-test"})
	t.Cleanup(func() { tokens.SetPlatformAudiences(nil) })
	s := signIn(t, "acct-1", "")
	rt := s.tokens["refresh_token"].(string)
	refresh := func(client, scope string) (int, map[string]interface{}) {
		v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {client}}
		if scope != "" {
			v.Set("scope", scope)
		}
		return postForm(t, s.tokenHandler, "/token", v)
	}

	for _, scope := range []string{
		"audience:privasys-platform-test openid", // another platform
		"openid address",                         // not in the grant
	} {
		if c, b := refresh("privasys-cli", scope); c != http.StatusBadRequest || b["error"] != "invalid_scope" {
			t.Fatalf("refresh asking %q: %d %v, want invalid_scope", scope, c, b)
		}
	}
	// The same refresh token still works.
	c, b := refresh("privasys-cli", "")
	if c != http.StatusOK {
		t.Fatalf("refresh after refusals: %d %v", c, b)
	}
	// Rotation: the used token is spent once accepted.
	if c, _ := refresh("privasys-cli", ""); c == http.StatusOK {
		t.Fatal("a refresh token was accepted twice")
	}

	// Another client is refused (an unknown one before the token is read).
	rt = b["refresh_token"].(string)
	if c, _ := refresh("someone-else", ""); c == http.StatusOK {
		t.Fatal("another client's refresh was accepted")
	}
	if c, b := refresh("privasys-cli", ""); c != http.StatusOK {
		t.Fatalf("the sign-in after an unknown client's attempt: %d %v", c, b)
	}
}

// The device flow (the CLI) signs in for one platform by naming its audience:
// that sign-in refreshes on its platform and never to the default one.
func TestADeviceSignInForOnePlatformStaysOnIt(t *testing.T) {
	tokens.SetPlatformAudiences([]string{"privasys-platform-test"})
	tokens.SetPlatformDomains([]string{"privasys-platform-test=test.example.org"})
	t.Cleanup(func() {
		tokens.SetPlatformDomains(nil)
		tokens.SetPlatformAudiences(nil)
	})
	s := signInScoped(t, "acct-1", "openid email profile offline_access audience:privasys-platform-test")
	if aud := claimsOf(t, s.tokens["access_token"].(string))["aud"]; aud != "privasys-platform-test" {
		t.Fatalf("sign-in aud %v", aud)
	}
	refresh := func(scope string) (int, map[string]interface{}) {
		v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.tokens["refresh_token"].(string)}, "client_id": {"privasys-cli"}}
		if scope != "" {
			v.Set("scope", scope)
		}
		return postForm(t, s.tokenHandler, "/token", v)
	}
	if c, _ := refresh("audience:privasys-platform openid"); c == http.StatusOK {
		t.Fatal("a test-platform sign-in minted the default platform")
	}
	c, b := refresh("")
	if c != http.StatusOK || claimsOf(t, b["access_token"].(string))["aud"] != "privasys-platform-test" {
		t.Fatalf("refresh on its own platform: %d %v", c, b)
	}
}

// signInScoped is signIn (shared subject) asking for `scope` at the device flow.
func signInScoped(t *testing.T, userID, scope string) signedIn {
	t.Helper()
	reg, db, iss := newDeviceTestEnv(t)
	_ = reg
	if _, err := db.Exec("INSERT OR IGNORE INTO users (user_id) VALUES (?)", userID); err != nil {
		t.Fatal(err)
	}
	codes, sessions, devices := NewCodeStore(), NewSessionStore(), NewDeviceStore()
	sessStore, err := idpsessions.New(db)
	if err != nil {
		t.Fatal(err)
	}
	iss.SetAccountResolver(sessStore.ActiveAccount)
	devHandler := HandleDeviceAuthorization(reg, sessions, devices, "https://privasys.id", nil)
	tokenHandler := HandleToken(reg, codes, devices, sessions, iss, db, sessStore)
	_, body := postForm(t, devHandler, "/device_authorization", url.Values{
		"client_id": {"privasys-cli"}, "scope": {scope}, "code_challenge": {testPKCEChallenge},
	})
	deviceCode := body["device_code"].(string)
	da, _ := devices.GetByDeviceCode(deviceCode)
	da.Interval = 0
	simulateWalletApproval(t, db, codes, sessions, deviceCode, devices, userID)
	c, b := postForm(t, tokenHandler, "/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {deviceCode},
		"client_id": {"privasys-cli"}, "code_verifier": {testPKCEVerifier},
	})
	if c != http.StatusOK {
		t.Fatalf("token: %d %v", c, b)
	}
	return signedIn{tokens: b, issuer: iss, db: db, tokenHandler: tokenHandler}
}
