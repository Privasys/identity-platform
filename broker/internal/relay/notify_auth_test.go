// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A send carries the push service's access token when one is configured, and
// no Authorization header at all when none is.
func TestNotifyAuthenticatesToThePushService(t *testing.T) {
	for _, token := range []string{"", "tok-123"} {
		var got []string
		expo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Values("Authorization")
			w.Write([]byte(`{"data":{"status":"ok"}}`))
		}))
		body := `{"pushToken":"ExponentPushToken[x]","sessionId":"s","rpId":"privasys.id"}`
		rec := httptest.NewRecorder()
		HandleNotify(rec, httptest.NewRequest(http.MethodPost, "/notify", strings.NewReader(body)), expo.URL, token)
		expo.Close()
		if rec.Code != http.StatusOK {
			t.Fatalf("token %q: status %d %s", token, rec.Code, rec.Body)
		}
		if token == "" && len(got) != 0 {
			t.Fatalf("no token configured, yet sent %v", got)
		}
		if token != "" && (len(got) != 1 || got[0] != "Bearer "+token) {
			t.Fatalf("Authorization = %v", got)
		}
		if strings.Contains(rec.Body.String(), "tok-123") {
			t.Fatal("the access token reached the caller")
		}
	}
}

// A refusal by the push service is reported to the caller without its body.
func TestNotifyReportsARefusalWithoutItsBody(t *testing.T) {
	expo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errors":[{"code":"AUTHENTICATION_ERROR","message":"secret detail"}]}`))
	}))
	defer expo.Close()
	body := `{"pushToken":"ExponentPushToken[x]","sessionId":"s","rpId":"privasys.id"}`
	rec := httptest.NewRecorder()
	HandleNotify(rec, httptest.NewRequest(http.MethodPost, "/notify", strings.NewReader(body)), expo.URL, "bad")
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "secret detail") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
