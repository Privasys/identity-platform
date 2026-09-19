// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package capasks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestListsOnlyTheHoldersLiveAsksNewestFirst(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := newStore(c.now)
	s.Put("alice", "n1", "a.example", "id1", "App One")
	c.t = c.t.Add(time.Minute)
	s.Put("alice", "n2", "b.example", "id2", "App Two")
	s.Put("bob", "n3", "c.example", "", "")

	got := s.ListFor("alice")
	if len(got) != 2 || got[0].Nonce != "n2" || got[1].Nonce != "n1" {
		t.Fatalf("alice sees %+v, want n2 then n1", got)
	}
	if got := s.ListFor("carol"); len(got) != 0 {
		t.Fatalf("carol sees %+v, want nothing", got)
	}

	// n1 was put a minute before n2, so it expires first.
	c.t = time.Unix(1_000_000, 0).Add(TTL)
	got = s.ListFor("alice")
	if len(got) != 1 || got[0].Nonce != "n2" {
		t.Fatalf("after n1 expires alice sees %+v, want only n2", got)
	}
}

func TestRemoveNeverTouchesAnotherHolder(t *testing.T) {
	s := newStore(time.Now)
	s.Put("alice", "shared", "a.example", "", "")
	s.Put("bob", "shared", "a.example", "", "")
	s.Remove("bob", "shared")
	if len(s.ListFor("alice")) != 1 {
		t.Fatal("bob's dismiss removed alice's ask")
	}
	if len(s.ListFor("bob")) != 0 {
		t.Fatal("bob's ask survived its own dismiss")
	}
}

func TestIncompleteAsksAreNotRecorded(t *testing.T) {
	s := newStore(time.Now)
	s.Put("alice", "", "a.example", "", "")
	s.Put("alice", "n1", "", "", "")
	s.Put("", "n1", "a.example", "", "")
	if len(s.ListFor("alice")) != 0 || len(s.ListFor("")) != 0 {
		t.Fatal("an ask without a nonce, a host or a holder was recorded")
	}
}

func TestBoundedPerHolderDroppingTheOldest(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := newStore(c.now)
	for i := 0; i < maxPerHolder+5; i++ {
		c.t = c.t.Add(time.Second)
		s.Put("alice", string(rune('A'+i)), "a.example", "", "")
	}
	got := s.ListFor("alice")
	if len(got) != maxPerHolder {
		t.Fatalf("alice holds %d asks, want %d", len(got), maxPerHolder)
	}
	if got[len(got)-1].Nonce != string(rune('A'+5)) {
		t.Fatalf("oldest kept is %q, want the sixth one put", got[len(got)-1].Nonce)
	}
}

func TestHandlers(t *testing.T) {
	s := newStore(time.Now)
	s.Put("alice", "n1", "a.example", "id1", "App One")
	auth := func(w http.ResponseWriter, r *http.Request) string {
		if r.Header.Get("Authorization") != "Bearer alice" {
			http.Error(w, "no", http.StatusUnauthorized)
			return ""
		}
		return "alice"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /capability-requests/pending", HandleList(s, auth))
	mux.HandleFunc("DELETE /capability-requests/pending/{nonce}", HandleDismiss(s, auth))

	do := func(method, path, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := do("GET", "/capability-requests/pending", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list: %d, want 401", rec.Code)
	}
	rec := do("GET", "/capability-requests/pending", "alice")
	var body struct{ Pending []Ask }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Pending) != 1 || body.Pending[0].AppName != "App One" {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do("DELETE", "/capability-requests/pending/n1", "alice"); rec.Code != http.StatusNoContent {
		t.Fatalf("dismiss: %d, want 204", rec.Code)
	}
	if len(s.ListFor("alice")) != 0 {
		t.Fatal("dismissed ask still listed")
	}
	if rec := do("DELETE", "/capability-requests/pending/n1", "alice"); rec.Code != http.StatusNoContent {
		t.Fatalf("second dismiss: %d, want 204", rec.Code)
	}
}
