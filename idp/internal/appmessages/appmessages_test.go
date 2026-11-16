// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package appmessages

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func testStore(t *testing.T, now *time.Time) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := open(db, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTheBannerComesFromTheClosedList(t *testing.T) {
	if BannerBody("invitation") != "You have a new invitation." {
		t.Fatal("invitation")
	}
	if BannerBody("update") != genericBody || BannerBody("") != genericBody {
		t.Fatal("an unknown kind must fall back to the generic body")
	}
}

func TestParse(t *testing.T) {
	ok := []string{
		`{"kind":"request"}`,
		`{"kind":"update"}`, // unknown kinds pass and get the generic banner
		`{"kind":"invitation","path":"/rooms/1?x=2#y","presented":{"name":"Ada"}}`,
	}
	for _, p := range ok {
		if _, err := Parse(json.RawMessage(p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	bad := []string{``, `[]`, `{}`, `{"kind":"request","path":"rooms"}`, `{"kind":"request","path":"/a b"}`,
		`{"kind":"request","path":"/\evil"}`}
	for _, p := range bad {
		if _, err := Parse(json.RawMessage(p)); err == nil {
			t.Errorf("%s: accepted", p)
		}
	}
}

func TestTheListIsPerHolderNewestFirstAndExpires(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := testStore(t, &now)
	a, _ := s.Put("alice", Message{Kind: "request", AppID: "app-1"})
	now = now.Add(time.Minute)
	b, _ := s.Put("alice", Message{Kind: "invitation", AppID: "app-2"})
	if id, _ := s.Put("alice", Message{Kind: "reminder"}); id != "" {
		t.Fatal("a reminder does not wait on the holder")
	}
	s.Put("bob", Message{Kind: "request"})

	got := s.ListFor("alice")
	if len(got) != 2 || got[0].ID != b || got[1].ID != a {
		t.Fatalf("list: %+v", got)
	}

	s.Remove("bob", a) // someone else's id is never touched
	if len(s.ListFor("alice")) != 2 {
		t.Fatal("bob removed alice's message")
	}
	s.RemoveByApp("alice", "app-1")
	if got := s.ListFor("alice"); len(got) != 1 || got[0].ID != b {
		t.Fatalf("after removing app-1: %+v", got)
	}

	now = now.Add(TTL + time.Second)
	if len(s.ListFor("alice")) != 0 {
		t.Fatal("expired messages are still listed")
	}
}

func TestOneHolderIsBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := testStore(t, &now)
	for i := 0; i < maxPerHolder+5; i++ {
		now = now.Add(time.Second)
		s.Put("alice", Message{Kind: "request"})
	}
	if n := len(s.ListFor("alice")); n != maxPerHolder {
		t.Fatalf("%d listed, want %d", n, maxPerHolder)
	}
}
