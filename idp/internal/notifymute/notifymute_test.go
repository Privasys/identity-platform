// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package notifymute

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	appA = "11111111-2222-3333-4444-555555555555"
	appB = "99999999-8888-7777-6666-555555555555"
)

type memStore struct{ rows map[string]bool }

func (m *memStore) MuteNotify(h string) error   { m.rows[h] = true; return nil }
func (m *memStore) UnmuteNotify(h string) error { delete(m.rows, h); return nil }
func (m *memStore) IsNotifyMuted(h string) bool { return m.rows[h] }

func newTest() (*Service, *memStore) {
	m := &memStore{rows: map[string]bool{}}
	return New(m, []byte("0123456789abcdef0123456789abcdef")), m
}

func call(h http.HandlerFunc, method, appID, bearer string) int {
	req := httptest.NewRequest(method, "/wallet/notify-mutes/"+appID, nil)
	req.SetPathValue("app_id", appID)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code
}

func auth(w http.ResponseWriter, r *http.Request) string {
	sub := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if sub == "" {
		http.Error(w, "no", http.StatusUnauthorized)
	}
	return sub
}

func TestAMuteSilencesOneAppForOneHolder(t *testing.T) {
	s, _ := newTest()
	if code := call(s.HandleMute(auth), "PUT", appA, "alice"); code != http.StatusNoContent {
		t.Fatalf("mute: %d", code)
	}
	if !s.Silenced("alice", appA, "app-message") {
		t.Fatal("the muted app still reaches her")
	}
	if s.Silenced("alice", appB, "app-message") {
		t.Fatal("muting one app silenced another")
	}
	if s.Silenced("bob", appA, "app-message") {
		t.Fatal("her mute silenced the app for someone else")
	}
	// The id arrives in any case; it is the same app.
	if !s.Silenced("alice", strings.ToUpper(appA), "share-decision") {
		t.Fatal("the same app id in upper case was not recognised")
	}

	if code := call(s.HandleUnmute(auth), "DELETE", appA, "alice"); code != http.StatusNoContent {
		t.Fatalf("unmute: %d", code)
	}
	if s.Silenced("alice", appA, "app-message") {
		t.Fatal("still silenced after unmuting")
	}
	// Idempotent both ways.
	if code := call(s.HandleUnmute(auth), "DELETE", appA, "alice"); code != http.StatusNoContent {
		t.Fatalf("second unmute: %d", code)
	}
}

func TestAnAccessRequestAlwaysArrives(t *testing.T) {
	s, _ := newTest()
	call(s.HandleMute(auth), "PUT", appA, "alice")
	for _, typ := range []string{"capability-request", "share-request"} {
		if s.Silenced("alice", appA, typ) {
			t.Fatalf("a mute silenced %s, a request the holder has to answer", typ)
		}
	}
	if !s.Silenced("alice", appA, "share-decision") {
		t.Fatal("a mute let an ordinary notification through")
	}
}

func TestTheStoredRowNamesNeitherHalf(t *testing.T) {
	s, m := newTest()
	call(s.HandleMute(auth), "PUT", appA, "alice")
	if len(m.rows) != 1 {
		t.Fatalf("%d rows stored, want 1", len(m.rows))
	}
	for row := range m.rows {
		if strings.Contains(row, "alice") || strings.Contains(row, appA) || strings.Contains(row, "11111111") {
			t.Fatalf("the stored row carries the pair: %q", row)
		}
		if len(row) != 64 {
			t.Fatalf("stored row is %d chars, want a 64-char hash", len(row))
		}
	}
	// Under another key the same pair is a different row: the table cannot be
	// matched against without the key.
	other := New(m, []byte("another-key-another-key-another-"))
	if other.Silenced("alice", appA, "app-message") {
		t.Fatal("the row matched under a different key")
	}
}

func TestRefusals(t *testing.T) {
	s, m := newTest()
	if code := call(s.HandleMute(auth), "PUT", appA, ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d, want 401", code)
	}
	if code := call(s.HandleMute(auth), "PUT", "not-an-app", "alice"); code != http.StatusBadRequest {
		t.Fatalf("bad app id: %d, want 400", code)
	}
	if len(m.rows) != 0 {
		t.Fatal("a refused call stored a row")
	}
	// A nil service (mutes not wired) silences nothing.
	var none *Service
	if none.Silenced("alice", appA, "app-message") {
		t.Fatal("a nil service silenced something")
	}
}
