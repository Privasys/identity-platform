// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build cgo

package sessions

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

func TestAPIKeyCreateListRevoke(t *testing.T) {
	s := newTestStore(t)
	iss, err := tokens.NewIssuer(filepath.Join(t.TempDir(), "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	userTok, err := iss.IssueAccessToken("user-1", "aud", nil, nil)
	if err != nil {
		t.Fatalf("user token: %v", err)
	}
	authed := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+userTok)
		return r
	}

	// Create.
	rec := httptest.NewRecorder()
	s.HandleCreateAPIKey(iss, "privasys-inference")(rec, authed("POST", "/api-keys", `{"label":"my key"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ SID, Label, Token string }
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.SID == "" || created.Token == "" || created.Label != "my key" {
		t.Fatalf("bad create response: %+v", created)
	}
	// The minted token verifies and carries the sub + sid.
	claims, err := iss.VerifyAccessToken(created.Token)
	if err != nil {
		t.Fatalf("verify minted token: %v", err)
	}
	if claims["sub"] != "user-1" || claims["sid"] != created.SID {
		t.Fatalf("minted token claims: %+v", claims)
	}

	// List shows it with its label.
	rec = httptest.NewRecorder()
	s.HandleListAPIKeys(iss)(rec, authed("GET", "/api-keys", ""))
	var listed struct {
		APIKeys []struct{ SID, Label string } `json:"api_keys"`
	}
	json.Unmarshal(rec.Body.Bytes(), &listed)
	if len(listed.APIKeys) != 1 || listed.APIKeys[0].SID != created.SID || listed.APIKeys[0].Label != "my key" {
		t.Fatalf("list: %+v", listed)
	}

	// Revoke → gone from the list, present in the revoked feed.
	since := time.Now().Add(-time.Minute).Unix()
	if err := s.Revoke(created.SID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rec = httptest.NewRecorder()
	s.HandleListAPIKeys(iss)(rec, authed("GET", "/api-keys", ""))
	listed.APIKeys = nil
	json.Unmarshal(rec.Body.Bytes(), &listed)
	if len(listed.APIKeys) != 0 {
		t.Fatalf("expected 0 keys after revoke: %+v", listed)
	}
	revoked, err := s.ListRevokedSince(since)
	if err != nil {
		t.Fatalf("ListRevokedSince: %v", err)
	}
	found := false
	for _, sid := range revoked {
		if sid == created.SID {
			found = true
		}
	}
	if !found {
		t.Fatalf("revoked feed missing sid %q: %v", created.SID, revoked)
	}
}

func TestAPIKeyCreateRequiresAuth(t *testing.T) {
	s := newTestStore(t)
	iss, err := tokens.NewIssuer(filepath.Join(t.TempDir(), "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	rec := httptest.NewRecorder()
	s.HandleCreateAPIKey(iss, "aud")(rec, httptest.NewRequest("POST", "/api-keys", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous create should be 401, got %d", rec.Code)
	}
}

// A key addressed to one app: who may ask, and what it carries.
func TestAppKey(t *testing.T) {
	s := newTestStore(t)
	iss, err := tokens.NewIssuer(filepath.Join(t.TempDir(), "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	s.SetWalletSessionResolver(func(token string) (string, bool) {
		return "user-1", token == "good"
	})
	const app = "02104572ca2f41e8ae2d24c0294e6f5e"
	s.SetAppSubjectResolver(func(appID, tool string) (string, string, string, error) {
		if appID != app && appID != "02104572-ca2f-41e8-ae2d-24c0294e6f5e" {
			return "", "", "", http.ErrNotSupported
		}
		if tool != WalletToolClientID {
			t.Fatalf("tool = %q", tool)
		}
		return app, "the-apps-own-sector", "the-apps-client", nil
	})
	post := func(auth, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api-keys", strings.NewReader(body))
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		s.HandleCreateAPIKey(iss, "privasys-inference")(rec, r)
		return rec
	}

	rec := post("Bearer wallet:good", `{"label":"Privasys Wallet","app_id":"02104572-ca2f-41e8-ae2d-24c0294e6f5e"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		SID, Token, Audience string
		ExpiresAt            int64 `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	claims, err := iss.VerifyAccessToken(out.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := iss.SubjectFor("user-1", "the-apps-own-sector")
	if claims["sub"] != want || want == "user-1" {
		t.Fatalf("sub = %v, want the app's own subject %v", claims["sub"], want)
	}
	if claims["aud"] != "app:"+app || out.Audience != "app:"+app {
		t.Fatalf("aud = %v (%s)", claims["aud"], out.Audience)
	}
	if claims["azp"] != WalletToolClientID || claims["sid"] != out.SID {
		t.Fatalf("azp, sid = %v, %v", claims["azp"], claims["sid"])
	}
	for _, c := range []string{"roles", "privasys_account"} {
		if _, has := claims[c]; has {
			t.Fatalf("an app key carries %s: %v", c, claims[c])
		}
	}
	if left := time.Until(time.Unix(out.ExpiresAt, 0)); left > AppKeyTTL+time.Minute || left < AppKeyTTL-time.Minute {
		t.Fatalf("lifetime %v, want about %v", left, AppKeyTTL)
	}
	// Not among the person's API keys.
	keys, err := s.ListAPIKeysByUser("user-1")
	if err != nil || len(keys) != 0 {
		t.Fatalf("api keys listed: %d, %v", len(keys), err)
	}
	// The platform can find the account behind the app's subject.
	if got, ok := s.HolderOf(want, "the-apps-client"); !ok || got != "user-1" {
		t.Fatalf("holder = %q, %v", got, ok)
	}

	userTok, err := iss.IssueAccessToken("user-1", "privasys-platform", nil, nil)
	if err != nil {
		t.Fatalf("user token: %v", err)
	}
	for name, c := range map[string]struct {
		auth, body string
		code       int
	}{
		"an access token cannot ask":        {"Bearer " + userTok, `{"app_id":"` + app + `"}`, http.StatusForbidden},
		"a platform audience is refused":    {"Bearer wallet:good", `{"app_id":"` + app + `","audience":"privasys-platform"}`, http.StatusBadRequest},
		"another app's audience is refused": {"Bearer wallet:good", `{"app_id":"` + app + `","audience":"app:ffffffffffffffffffffffffffffffff"}`, http.StatusBadRequest},
		"a client cannot be named too":      {"Bearer wallet:good", `{"app_id":"` + app + `","client_id":"privasys-drive"}`, http.StatusBadRequest},
		"an unknown app is refused":         {"Bearer wallet:good", `{"app_id":"not-an-app"}`, http.StatusBadRequest},
		"a bad wallet session is refused":   {"Bearer wallet:bad", `{"app_id":"` + app + `"}`, http.StatusUnauthorized},
	} {
		if rec := post(c.auth, c.body); rec.Code != c.code {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body.String(), c.code)
		}
	}
	// Its own audience, said out loud, is accepted.
	if rec := post("Bearer wallet:good", `{"app_id":"`+app+`","audience":"app:`+app+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("own audience: %d %s", rec.Code, rec.Body.String())
	}
}
