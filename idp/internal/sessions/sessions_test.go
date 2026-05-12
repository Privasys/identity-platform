// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build cgo

package sessions

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatalf("new sessions: %v", err)
	}
	return s
}

func TestCreateAndIsActive(t *testing.T) {
	s := newTestStore(t)
	row, err := s.Create("", "user-1", "client-a", "device-x", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if row.SID == "" {
		t.Fatal("SID empty")
	}
	if !s.IsActive(row.SID) {
		t.Fatal("expected active")
	}
}

func TestRevokeMakesInactive(t *testing.T) {
	s := newTestStore(t)
	row, err := s.Create("", "user-1", "client-a", "", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Revoke(row.SID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if s.IsActive(row.SID) {
		t.Fatal("expected inactive after revoke")
	}
	// Touch on a revoked session reports ErrRevoked.
	if err := s.Touch(row.SID, time.Hour); err != ErrRevoked {
		t.Fatalf("Touch revoked: got %v want ErrRevoked", err)
	}
}

func TestTouchExtends(t *testing.T) {
	s := newTestStore(t)
	row, err := s.Create("", "user-1", "client-a", "", time.Minute)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	original := row.ExpiresAt
	time.Sleep(5 * time.Millisecond)
	if err := s.Touch(row.SID, time.Hour); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := s.Get(row.SID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.ExpiresAt.After(original) {
		t.Fatalf("expires_at not extended: %v <= %v", got.ExpiresAt, original)
	}
}

func TestListByUser(t *testing.T) {
	s := newTestStore(t)
	a, _ := s.Create("", "user-1", "client-a", "", time.Hour)
	b, _ := s.Create("", "user-1", "client-b", "", time.Hour)
	_, _ = s.Create("", "user-2", "client-a", "", time.Hour)

	list, err := s.ListByUser("user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len=%d want 2", len(list))
	}
	// Revoked rows are excluded.
	_ = s.Revoke(a.SID)
	list, _ = s.ListByUser("user-1")
	if len(list) != 1 || list[0].SID != b.SID {
		t.Fatalf("expected only b, got %#v", list)
	}
}

func TestNewSIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		sid := NewSID()
		if seen[sid] {
			t.Fatalf("duplicate SID: %s", sid)
		}
		seen[sid] = true
	}
}
