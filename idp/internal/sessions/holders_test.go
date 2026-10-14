// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessions

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/store"
)

// newHolderStore opens a fresh store. (sessions_test.go's helper is behind a
// cgo build tag that this file does not need.)
func newHolderStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A relationship row is the one way from the subject an app sees back to the
// account: written at sign-in, gone when the holder removes the app, and
// never touched by a phone change.
func TestRelationshipRows(t *testing.T) {
	s := newHolderStore(t)
	if err := s.RecordHolder("sub-a", "app-a", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordHolder("sub-a2", "app-a", "alice"); err == nil {
		// A second subject for the same pair is a different row; both
		// resolve (a client moved sectors keeps its old rows until removal).
	}
	if u, ok := s.HolderOf("sub-a", "app-a"); !ok || u != "alice" {
		t.Fatalf("holder of sub-a: %q %v", u, ok)
	}
	if _, ok := s.HolderOf("sub-a", "app-b"); ok {
		t.Fatal("another client resolved alice's subject")
	}
	if _, ok := s.HolderOf("sub-x", "app-a"); ok {
		t.Fatal("an unknown subject resolved")
	}

	// Sessions of the pair end with the relationship; another client's stay.
	a1, _ := s.Create("", "alice", "app-a", "", time.Hour)
	a2, _ := s.Create("", "alice", "app-a", "d2", time.Hour)
	b1, _ := s.Create("", "alice", "app-b", "", time.Hour)
	var hooked []string
	s.SetRevokeHook(func(sid string) { hooked = append(hooked, sid) })
	n, err := s.RemoveHolder("alice", "app-a")
	if err != nil || n != 2 {
		t.Fatalf("remove: n=%d err=%v", n, err)
	}
	if _, ok := s.HolderOf("sub-a", "app-a"); ok {
		t.Fatal("the relationship survived removal")
	}
	if s.IsActive(a1.SID) || s.IsActive(a2.SID) || !s.IsActive(b1.SID) {
		t.Fatal("wrong sessions ended")
	}
	if len(hooked) != 2 {
		t.Fatalf("revoke hook ran for %v", hooked)
	}

	// A phone revoke or a recovery ends sessions, not relationships.
	if err := s.RecordHolder("sub-a", "app-a", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAllForUser("alice"); err != nil {
		t.Fatal(err)
	}
	if u, ok := s.HolderOf("sub-a", "app-a"); !ok || u != "alice" {
		t.Fatal("a session revoke removed the relationship")
	}
}

// The account resolver behind token verification answers only for a live
// session.
func TestActiveAccount(t *testing.T) {
	s := newHolderStore(t)
	sess, _ := s.Create("", "bob", "app", "", time.Hour)
	if u, ok := s.ActiveAccount(sess.SID); !ok || u != "bob" {
		t.Fatalf("live: %q %v", u, ok)
	}
	_ = s.Revoke(sess.SID)
	if _, ok := s.ActiveAccount(sess.SID); ok {
		t.Fatal("a revoked session still named its account")
	}
	if _, ok := s.ActiveAccount("nope"); ok {
		t.Fatal("an unknown session named an account")
	}
}

// Rows for pairs that predate the table come from the live sessions, with
// the subject derived forward; a second pass writes nothing.
func TestBackfillHolders(t *testing.T) {
	s := newHolderStore(t)
	_, _ = s.Create("", "alice", "app-a", "", time.Hour)
	_, _ = s.Create("", "alice", "app-a", "d2", time.Hour)
	_, _ = s.Create("", "bob", "app-b", "", time.Hour)
	gone, _ := s.Create("", "carol", "app-c", "", time.Hour)
	_ = s.Revoke(gone.SID)
	derive := func(user, client string) string { return "sub:" + user + "@" + client }
	n, err := s.BackfillHolders(derive)
	if err != nil || n != 2 {
		t.Fatalf("backfill: n=%d err=%v", n, err)
	}
	if u, ok := s.HolderOf("sub:alice@app-a", "app-a"); !ok || u != "alice" {
		t.Fatal("alice's row missing")
	}
	if _, ok := s.HolderOf("sub:carol@app-c", "app-c"); ok {
		t.Fatal("a revoked session produced a relationship")
	}
	if n, _ := s.BackfillHolders(derive); n != 0 {
		t.Fatalf("second pass wrote %d", n)
	}
}

// Removing a phone, or recovering the account, ends every sealed session of
// the account: they would otherwise rebind on their vouchers for 90 days.
func TestRevokeAllForUserEndsEverySession(t *testing.T) {
	s := newHolderStore(t)
	var hooked []string
	s.SetRevokeHook(func(sid string) { hooked = append(hooked, sid) })
	a, _ := s.FindOrCreateForApp("alice", "app-1", "", time.Hour)
	b, _ := s.FindOrCreateForApp("alice", "app-2", "", time.Hour)
	c, _ := s.FindOrCreateForApp("bob", "app-1", "", time.Hour)
	n, err := s.RevokeAllForUser("alice")
	if err != nil || n != 2 {
		t.Fatalf("revoke all: n=%d err=%v", n, err)
	}
	if s.IsActive(a.SID) || s.IsActive(b.SID) || !s.IsActive(c.SID) {
		t.Fatal("wrong sessions ended")
	}
	if len(hooked) != 2 {
		t.Fatalf("hook ran for %v", hooked)
	}
}
