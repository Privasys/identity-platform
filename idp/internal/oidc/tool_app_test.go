// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"net/http"
	"net/url"
	"testing"

	idpsessions "github.com/Privasys/idp/internal/sessions"
	"github.com/Privasys/idp/internal/tokens"
)

// A tool client (the explorer) asking for one app gets a token for that app,
// in the subject the app knows the person by, naming itself as azp, with no
// platform audience, account or roles; a refresh never mints for another app.
func TestAToolClientsTokenIsForTheAppItReaches(t *testing.T) {
	const app = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	reg, db, iss := newDeviceTestEnv(t)
	if _, err := reg.RegisterWithID("site", "Site", nil, "", []string{"email"}); err != nil {
		t.Fatal(err)
	}
	for _, step := range []error{
		reg.SetSector("site", "site"),
		reg.SetAppIDs("site", []string{app}),
		reg.SetSector("privasys-cli", "privasys-cli"),
		reg.SetAnyAppAudience("privasys-cli", true),
	} {
		if step != nil {
			t.Fatal(step)
		}
	}
	if _, err := db.Exec("INSERT OR IGNORE INTO users (user_id) VALUES ('acct-1')"); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantRole("acct-1", "privasys-platform:admin", "test"); err != nil {
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
		"client_id":      {"privasys-cli"},
		"scope":          {"openid offline_access audience:app:" + app},
		"code_challenge": {testPKCEChallenge},
	})
	deviceCode := body["device_code"].(string)
	da, _ := devices.GetByDeviceCode(deviceCode)
	da.Interval = 0
	simulateWalletApproval(t, db, codes, sessions, deviceCode, devices, "acct-1")
	c, b := postForm(t, tokenHandler, "/token", url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {"privasys-cli"},
		"code_verifier": {testPKCEVerifier},
	})
	if c != http.StatusOK {
		t.Fatalf("token: %d %v", c, b)
	}

	appSub := iss.SubjectFor("acct-1", "site")
	check := func(what string, accessToken string) {
		t.Helper()
		at := claimsOf(t, accessToken)
		if at["aud"] != "app:"+app || at["sub"] != appSub || at["azp"] != "privasys-cli" {
			t.Fatalf("%s: aud %v sub %v azp %v; want app:%s, the app's own subject, the tool", what, at["aud"], at["sub"], at["azp"], app)
		}
		if _, has := at["roles"]; has {
			t.Fatalf("%s: a tool's token carries roles: %v", what, at["roles"])
		}
		if _, has := at[tokens.ClaimPrivasysAccount]; has {
			t.Fatalf("%s: a tool's token names the account", what)
		}
	}
	check("code exchange", b["access_token"].(string))
	// The ID token is the tool's own: who the person is to the tool.
	if sub := claimsOf(t, b["id_token"].(string))["sub"]; sub != iss.SubjectFor("acct-1", "privasys-cli") {
		t.Fatalf("id token sub %v, want the tool's own subject", sub)
	}
	// The app's subject leads back to the account through its own client.
	if acct, ok := sessStore.HolderOf(appSub, "site"); !ok || acct != "acct-1" {
		t.Fatalf("relationship row for the app's subject: %q %v", acct, ok)
	}

	refresh := func(token, scope string) (int, map[string]interface{}) {
		v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {"privasys-cli"}}
		if scope != "" {
			v.Set("scope", scope)
		}
		return postForm(t, tokenHandler, "/token", v)
	}
	c, r := refresh(b["refresh_token"].(string), "")
	if c != http.StatusOK {
		t.Fatalf("refresh: %d %v", c, r)
	}
	check("refresh", r["access_token"].(string))
	if c, r := refresh(r["refresh_token"].(string), "audience:app:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb openid"); c == http.StatusOK {
		t.Fatalf("a refresh minted for another app: %v", r)
	}
}
