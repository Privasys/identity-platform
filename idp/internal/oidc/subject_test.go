// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// claimsOf decodes a JWT's payload without verifying it.
func claimsOf(t *testing.T, jwt string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	var c map[string]interface{}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	return c
}

type signedIn struct {
	tokens       map[string]interface{}
	issuer       *tokens.Issuer
	db           *store.DB
	tokenHandler http.HandlerFunc
}

// signIn runs the device flow for the CLI client as `userID`, with the client
// in `sector` ("" for the shared one), and returns the token response.
func signIn(t *testing.T, userID, sector string) signedIn {
	t.Helper()
	return signInWith(t, userID, sector, false)
}

func signInWith(t *testing.T, userID, sector string, platform bool) signedIn {
	t.Helper()
	reg, db, iss := newDeviceTestEnv(t)
	iss.SetSubjectStore(db)
	if sector != "" {
		if err := reg.SetSector("privasys-cli", sector); err != nil {
			t.Fatal(err)
		}
	}
	if platform {
		if err := reg.SetPlatform("privasys-cli", true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT OR IGNORE INTO users (user_id) VALUES (?)", userID); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantRole(userID, "privasys-platform:admin", "test"); err != nil {
		t.Fatal(err)
	}
	codes, sessions, devices := NewCodeStore(), NewSessionStore(), NewDeviceStore()
	devHandler := HandleDeviceAuthorization(reg, sessions, devices, "https://privasys.id", nil)
	tokenHandler := HandleToken(reg, codes, devices, sessions, iss, db, nil)
	_, body := postForm(t, devHandler, "/device_authorization", url.Values{
		"client_id":      {"privasys-cli"},
		"scope":          {"openid email profile offline_access"},
		"code_challenge": {testPKCEChallenge},
	})
	deviceCode := body["device_code"].(string)
	da, _ := devices.GetByDeviceCode(deviceCode)
	da.Interval = 0
	simulateWalletApproval(t, db, codes, sessions, deviceCode, devices, userID)
	c, b := postForm(t, tokenHandler, "/token", url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {"privasys-cli"},
		"code_verifier": {testPKCEVerifier},
	})
	if c != http.StatusOK {
		t.Fatalf("token: %d %v", c, b)
	}
	return signedIn{tokens: b, issuer: iss, db: db, tokenHandler: tokenHandler}
}

func userinfo(t *testing.T, s signedIn) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+s.tokens["access_token"].(string))
	rec := httptest.NewRecorder()
	HandleUserInfo(s.issuer, s.db)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo: %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&body)
	return body
}

func TestASharedSectorClientSeesTheAccount(t *testing.T) {
	s := signIn(t, "acct-1", "")
	if sub := claimsOf(t, s.tokens["id_token"].(string))["sub"]; sub != "acct-1" {
		t.Fatalf("shared-sector sub = %v, want the account id", sub)
	}
	info := userinfo(t, s)
	if info["sub"] != "acct-1" || info["roles"] == nil {
		t.Fatalf("shared-sector userinfo: %v", info)
	}
	at := claimsOf(t, s.tokens["access_token"].(string))
	if at["aud"] != "privasys-platform" || at[ClaimPrivasysAccount] != "acct-1" {
		t.Fatalf("legacy platform token: aud %v, account %v", at["aud"], at[ClaimPrivasysAccount])
	}
}

func TestAnOwnSectorClientSeesItsOwnSubject(t *testing.T) {
	s := signIn(t, "acct-1", "privasys-cli")
	idSub, _ := claimsOf(t, s.tokens["id_token"].(string))["sub"].(string)
	at := claimsOf(t, s.tokens["access_token"].(string))
	if idSub == "" || idSub == "acct-1" {
		t.Fatalf("own-sector sub = %q, want a subject that is not the account id", idSub)
	}
	if at["sub"] != idSub {
		t.Fatalf("access token sub %v differs from ID token sub %q", at["sub"], idSub)
	}
	if _, has := at["roles"]; has {
		t.Fatalf("an own-sector client was given the account's roles: %v", at["roles"])
	}
	// Its token is for itself, not the platform, and names no account.
	if at["aud"] != "privasys-cli" {
		t.Fatalf("own-subject client token aud %v, want the client itself", at["aud"])
	}
	if _, has := at[ClaimPrivasysAccount]; has {
		t.Fatal("an own-subject client's token carries the account id")
	}

	// The IdP itself still finds the account behind the subject.
	claims, err := s.issuer.VerifyAccessToken(s.tokens["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "acct-1" || claims[tokens.ClaimSubjectAsIssued] != idSub {
		t.Fatalf("verified claims: sub %v, as issued %v", claims["sub"], claims[tokens.ClaimSubjectAsIssued])
	}

	// Userinfo echoes the subject the client holds, and no roles.
	info := userinfo(t, s)
	if info["sub"] != idSub {
		t.Fatalf("userinfo sub %v, want %q", info["sub"], idSub)
	}
	if _, has := info["roles"]; has {
		t.Fatal("userinfo gave an own-sector client the account's roles")
	}

	// A refresh keeps the same subject.
	c, r := postForm(t, s.tokenHandler, "/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {s.tokens["refresh_token"].(string)},
		"client_id":     {"privasys-cli"},
	})
	if c != http.StatusOK {
		t.Fatalf("refresh: %d %v", c, r)
	}
	if sub := claimsOf(t, r["id_token"].(string))["sub"]; sub != idSub {
		t.Fatalf("refreshed sub %v, want %q", sub, idSub)
	}
}

func TestTwoSectorsCannotMatchAPerson(t *testing.T) {
	a := signIn(t, "acct-1", "site-a")
	b := signIn(t, "acct-1", "site-b")
	subA := claimsOf(t, a.tokens["id_token"].(string))["sub"]
	subB := claimsOf(t, b.tokens["id_token"].(string))["sub"]
	if subA == subB {
		t.Fatalf("two sectors got the same subject %v for one person", subA)
	}
}

// A first-party control-plane client (the portal, the CLI) may have its own
// subjects and still hold the platform audience, with the account and roles:
// the platform is Privasys itself.
func TestAPlatformClientWithItsOwnSubjects(t *testing.T) {
	s := signInWith(t, "acct-1", "privasys-cli", true)
	at := claimsOf(t, s.tokens["access_token"].(string))
	if at["sub"] == "acct-1" {
		t.Fatal("an own-subject platform client got the account id as sub")
	}
	if at["aud"] != "privasys-platform" || at[ClaimPrivasysAccount] != "acct-1" || at["roles"] == nil {
		t.Fatalf("platform client token: aud %v account %v roles %v", at["aud"], at[ClaimPrivasysAccount], at["roles"])
	}
	if info := userinfo(t, s); info["roles"] == nil {
		t.Fatal("userinfo dropped a platform client's roles")
	}
}
