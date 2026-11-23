package oidc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestSessionCompleteNeverTakesTheAccountFromTheRequest proves a pending
// session cannot be completed as an account the caller names.
func TestSessionCompleteNeverTakesTheAccountFromTheRequest(t *testing.T) {
	codes := NewCodeStore()
	sessions := NewSessionStore()
	sid := "s-pending"
	sessions.Create(&AuthSession{SessionID: sid, ClientID: "c", RedirectURI: "https://c.example/cb", ExpiresAt: time.Now().Add(time.Minute)})
	h := HandleSessionComplete(codes, sessions)

	body, _ := json.Marshal(map[string]any{"session_id": sid, "user_id": "victim-account"})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/session/complete", bytes.NewReader(body)))
	if rec.Code == http.StatusOK {
		t.Fatalf("an unauthenticated session was completed as a named account: %s", rec.Body.String())
	}
	if s, ok := sessions.Get(sid); !ok || s.Authenticated {
		t.Fatal("the session was marked authenticated")
	}
}
