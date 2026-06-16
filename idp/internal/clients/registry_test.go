// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package clients

import (
	"path/filepath"
	"testing"

	"github.com/Privasys/idp/internal/store"
)

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "idp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRegistry(db)
}

// Registering a client whose required_attributes contains a key that is not in
// the canonical referential must be refused — the "should not be possible"
// guarantee.
func TestRegister_RejectsNonCanonicalRequiredAttributes(t *testing.T) {
	reg := newTestRegistry(t)

	if _, err := reg.Register("Bad App", []string{"https://app/cb"}, "", []string{"language"}); err == nil {
		t.Fatal("Register accepted a non-canonical attribute 'language'; want error")
	}

	if _, err := reg.RegisterWithID("bad-id", "Bad App", []string{"https://app/cb"}, "", []string{"email", "not_a_real_attr"}); err == nil {
		t.Fatal("RegisterWithID accepted a non-canonical attribute; want error")
	}
}

// Canonical keys and an empty/nil whitelist are accepted.
func TestRegister_AcceptsCanonicalAndEmpty(t *testing.T) {
	reg := newTestRegistry(t)

	if _, err := reg.RegisterWithID("privasys-cli", "Privasys CLI", []string{"https://privasys.id/device"}, "", []string{"email", "name"}); err != nil {
		t.Fatalf("RegisterWithID with canonical attrs: %v", err)
	}

	if _, err := reg.Register("Open App", []string{"https://app/cb"}, "", nil); err != nil {
		t.Fatalf("Register with nil whitelist: %v", err)
	}
}
