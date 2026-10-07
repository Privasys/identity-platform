// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeDisclosureAuth struct{}

func (fakeDisclosureAuth) VerifyAppProof(_ context.Context, appID, proof string) (string, error) {
	if proof != "good" {
		return "", errors.New("bad proof")
	}
	return "Privasys Drive", nil
}

func (fakeDisclosureAuth) HasConsent(sub, appID string) bool {
	return sub == "sub-1" && appID == "app-1"
}

// TestAppInitiatedDisclosure walks the whole exchange: the app asks, the
// holder's wallet is pushed exactly the requested set, nothing is released
// until the holder approves, and the app then collects one disclosure that
// carries only what was asked for and is addressed to it alone.
func TestAppInitiatedDisclosure(t *testing.T) {
	reg, _, iss := newDeviceTestEnv(t)
	if _, err := reg.RegisterWithID(DisclosureClientID, "Privasys", []string{"http://localhost/cb"}, "",
		[]string{"name", "email"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	sessions := NewSessionStore()
	codes := NewCodeStore()
	store := NewDisclosureStore()
	var pushedSession *AuthSession
	var pushedAdded []string
	var pushedPayload map[string]interface{}
	push := func(sub string, s *AuthSession, added []string, payload map[string]interface{}) bool {
		if sub != "sub-1" {
			t.Errorf("pushed %q", sub)
		}
		pushedSession, pushedAdded, pushedPayload = s, added, payload
		return true
	}
	request := HandleDisclosureRequest(reg, sessions, nil, push, store, fakeDisclosureAuth{})
	result := HandleDisclosureResult(reg, sessions, codes, iss, store, fakeDisclosureAuth{})

	post := func(h http.HandlerFunc, path string, body any, id string) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", path, bytes.NewReader(b))
		if id != "" {
			req.SetPathValue("id", id)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	ask := map[string]any{"app_id": "app-1", "proof": "good", "sub": "sub-1",
		"attributes": []string{"name"}, "purpose": "for Bertrand to open Fundraising"}

	// Refusals first.
	bad := map[string]any{"app_id": "app-1", "proof": "forged", "sub": "sub-1", "attributes": []string{"name"}}
	if code, _ := post(request, "/disclosure/request", bad, ""); code != http.StatusUnauthorized {
		t.Fatalf("forged proof: %d", code)
	}
	stranger := map[string]any{"app_id": "app-1", "proof": "good", "sub": "sub-2", "attributes": []string{"name"}}
	if code, _ := post(request, "/disclosure/request", stranger, ""); code != http.StatusForbidden {
		t.Fatalf("holder without a relationship: %d", code)
	}

	code, out := post(request, "/disclosure/request", ask, "")
	if code != http.StatusAccepted {
		t.Fatalf("request: %d %v", code, out)
	}
	id, _ := out["id"].(string)
	if pushedSession == nil || strings.Join(pushedAdded, ",") != "name" ||
		pushedPayload["appName"] != "Privasys Drive" || pushedPayload["purpose"] == nil {
		t.Fatalf("push: %+v %v %v", pushedSession, pushedAdded, pushedPayload)
	}

	// Nothing is released before the holder approves.
	collect := map[string]any{"app_id": "app-1", "proof": "good"}
	if code, out := post(result, "/disclosure/x", collect, id); code != 200 || out["status"] != "pending" {
		t.Fatalf("before approval: %d %v", code, out)
	}
	// Another app cannot collect it.
	if code, _ := post(result, "/disclosure/x", map[string]any{"app_id": "app-2", "proof": "good"}, id); code != http.StatusNotFound {
		t.Fatalf("other app collected: %d", code)
	}

	// The wallet approves, as /fido2/attribute-approval/complete does.
	authCode := codes.Create(&AuthCode{ClientID: DisclosureClientID, UserID: "sub-1", Scope: "openid",
		NamedAttributes: pushedSession.NamedAttributes,
		Attributes:      map[string]string{"name": "Ada Lovelace", "email": "ada@example.org"}})
	if !sessions.CompleteIfPending(pushedSession.SessionID, "sub-1", authCode) {
		t.Fatal("completion refused")
	}

	code, out = post(result, "/disclosure/x", collect, id)
	if code != 200 || out["status"] != "approved" {
		t.Fatalf("after approval: %d %v", code, out)
	}
	parts := strings.Split(out["disclosure"].(string), ".")
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(hdr), `"disclosure+jwt"`) {
		t.Fatalf("typ: %s", hdr)
	}
	var claims map[string]any
	_ = json.Unmarshal(body, &claims)
	attrs, _ := claims["attrs"].(map[string]any)
	if claims["aud"] != "disclosure:app-1" || claims["sub"] != "sub-1" || attrs["name"] != "Ada Lovelace" {
		t.Fatalf("claims: %v", claims)
	}
	if _, leaked := attrs["email"]; leaked {
		t.Fatalf("an attribute nobody asked for was disclosed: %v", attrs)
	}
	// One collection only.
	if code, _ := post(result, "/disclosure/x", collect, id); code != http.StatusNotFound {
		t.Fatalf("collected twice: %d", code)
	}

	// An app cannot flood a wallet.
	for i := 0; i < maxPendingPerApp; i++ {
		if code, _ := post(request, "/disclosure/request", ask, ""); code != http.StatusAccepted {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code, _ := post(request, "/disclosure/request", ask, ""); code != http.StatusTooManyRequests {
		t.Fatalf("flood: %d", code)
	}
}
