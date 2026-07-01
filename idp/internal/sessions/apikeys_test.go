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
