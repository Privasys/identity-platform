// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/sessions"
)

func TestSubtractKeys(t *testing.T) {
	got := subtractKeys([]string{"sub", "email", "birthdate"}, []string{"sub", "email"})
	if !reflect.DeepEqual(got, []string{"birthdate"}) {
		t.Fatalf("subtractKeys = %v, want [birthdate]", got)
	}
	if got := subtractKeys([]string{"sub"}, []string{"sub", "email"}); got != nil {
		t.Fatalf("narrowing produced a delta: %v", got)
	}
}

func TestCompleteIfPending(t *testing.T) {
	ss := NewSessionStore()
	ss.Create(&AuthSession{SessionID: "s1", ExpiresAt: time.Now().Add(time.Minute)})

	if !ss.CompleteIfPending("s1", "u1", "code-1") {
		t.Fatal("first completion refused")
	}
	// A second completion must never override the first — the pushed
	// approval loses the race with a concurrent ceremony, not the reverse.
	if ss.CompleteIfPending("s1", "u2", "code-2") {
		t.Fatal("second completion overrode the first")
	}
	s, _ := ss.Get("s1")
	if s.UserID != "u1" || s.AuthCode != "code-1" {
		t.Fatalf("session mutated by the losing completion: %+v", s)
	}
	if ss.CompleteIfPending("unknown", "u1", "c") {
		t.Fatal("unknown session completed")
	}
}

// stepUpEnv builds an /authorize handler with the step-up arm wired to a
// recording push hook, plus a holder with a recorded granted set.
func stepUpEnv(t *testing.T, granted []string) (h func(q url.Values) map[string]interface{}, hint string, pushes *[][]string) {
	t.Helper()
	reg, db, iss := newDeviceTestEnv(t)
	if _, err := reg.RegisterWithID("qa-stepup", "Step-up QA",
		[]string{"http://localhost/cb"}, "", []string{"email", "name", "birthdate"}); err != nil {
		t.Fatalf("register client: %v", err)
	}
	sess, err := sessions.New(db)
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	row, err := sess.Create("", "sub-1", "qa-stepup", "", time.Hour)
	if err != nil {
		t.Fatalf("session row: %v", err)
	}
	if err := sess.SetGrantedAttributes(row.SID, granted); err != nil {
		t.Fatalf("record granted: %v", err)
	}
	tok, err := iss.IssueAccessTokenWithSID("sub-1", "privasys-platform", row.SID, nil, nil)
	if err != nil {
		t.Fatalf("issue hint token: %v", err)
	}

	recorded := &[][]string{}
	handler := HandleAuthorize(reg, NewSessionStore(), "https://privasys.id", nil,
		&AttributeStepUp{
			Issuer:   iss,
			Sessions: sess,
			Push: func(sub string, session *AuthSession, added []string, payload map[string]interface{}) bool {
				if sub != "sub-1" {
					t.Errorf("push sub = %q, want sub-1", sub)
				}
				if session.SessionID == "" || len(session.RequestedKeys) == 0 {
					t.Errorf("push session missing binding material: %+v", session)
				}
				*recorded = append(*recorded, added)
				return true
			},
		})

	call := func(q url.Values) map[string]interface{} {
		req := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("authorize %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode authorize response: %v", err)
		}
		return body
	}
	return call, tok, recorded
}

func stepUpQuery(hint string) url.Values {
	q := url.Values{}
	q.Set("client_id", "qa-stepup")
	q.Set("response_type", "code")
	q.Set("code_challenge", testPKCEChallenge)
	q.Set("scope", "openid email profile")
	if hint != "" {
		q.Set("session_hint", hint)
	}
	return q
}

func TestAuthorizeStepUpPushesOnlyTheDelta(t *testing.T) {
	call, hint, pushes := stepUpEnv(t, []string{"email", "name", "sub"})

	// Widen by one named attribute → exactly that key is pushed.
	q := stepUpQuery(hint)
	q.Set("attributes", "birthdate")
	body := call(q)
	su, ok := body["step_up"].(map[string]interface{})
	if !ok {
		t.Fatalf("no step_up in response: %v", body)
	}
	if su["pushed"] != true {
		t.Fatalf("step_up.pushed = %v", su["pushed"])
	}
	added, _ := su["added"].([]interface{})
	if len(added) != 1 || added[0] != "birthdate" {
		t.Fatalf("step_up.added = %v, want [birthdate]", added)
	}
	if len(*pushes) != 1 || !reflect.DeepEqual((*pushes)[0], []string{"birthdate"}) {
		t.Fatalf("push hook saw %v", *pushes)
	}
}

func TestAuthorizeStepUpNarrowingIsSilent(t *testing.T) {
	call, hint, pushes := stepUpEnv(t, []string{"birthdate", "email", "name", "sub"})

	// Same-or-narrower request → covered, no push, no step_up signal.
	body := call(stepUpQuery(hint))
	if _, ok := body["step_up"]; ok {
		t.Fatalf("narrowing produced a step_up: %v", body)
	}
	if len(*pushes) != 0 {
		t.Fatalf("narrowing pushed: %v", *pushes)
	}
}

func TestAuthorizeStepUpIgnoresBadHint(t *testing.T) {
	call, _, pushes := stepUpEnv(t, []string{"email", "sub"})

	// A hint that fails verification only disables the arm — the request
	// itself still succeeds (the hint authorises nothing either way).
	q := stepUpQuery("not-a-token")
	q.Set("attributes", "birthdate")
	body := call(q)
	if _, ok := body["step_up"]; ok {
		t.Fatalf("bad hint produced a step_up: %v", body)
	}
	if len(*pushes) != 0 {
		t.Fatalf("bad hint pushed: %v", *pushes)
	}
}

func TestAuthorizeStepUpNeverPushesPresence(t *testing.T) {
	call, hint, pushes := stepUpEnv(t, []string{"email", "name", "sub"})

	// The live presence ceremony cannot ride a one-tap push approval: a
	// delta containing holder_present forces the full wallet flow.
	q := stepUpQuery(hint)
	q.Set("acr_values", "gov-presence")
	body := call(q)
	if _, ok := body["step_up"]; ok {
		t.Fatalf("presence delta produced a step_up: %v", body)
	}
	if len(*pushes) != 0 {
		t.Fatalf("presence delta pushed: %v", *pushes)
	}
}

func TestGrantedAttributesRoundTrip(t *testing.T) {
	_, db, _ := newDeviceTestEnv(t)
	sess, err := sessions.New(db)
	if err != nil {
		t.Fatalf("sessions.New: %v", err)
	}
	if _, ok := sess.GrantedAttributesForApp("sub-1", "app-1"); ok {
		t.Fatal("granted set reported before any grant")
	}
	row, err := sess.Create("", "sub-1", "app-1", "", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := sess.SetGrantedAttributes(row.SID, []string{"name", "email", "sub"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := sess.GrantedAttributesForApp("sub-1", "app-1")
	if !ok || !reflect.DeepEqual(got, []string{"email", "name", "sub"}) {
		t.Fatalf("granted = %v ok=%v, want sorted [email name sub]", got, ok)
	}
	// Scoped per client: another app sees nothing.
	if _, ok := sess.GrantedAttributesForApp("sub-1", "app-2"); ok {
		t.Fatal("granted set leaked across clients")
	}
}
