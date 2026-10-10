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

// Canonical keys are accepted, and naming none is refused: the whitelist is how
// a relying party declares what it consumes, so registering without one asks for
// nothing. Accepting it would leave a client that can never sign anyone in,
// silently, at the point where the mistake is still cheap to say out loud.
func TestRegister_AcceptsCanonicalAndRequiresAWhitelist(t *testing.T) {
	reg := newTestRegistry(t)

	if _, err := reg.RegisterWithID("privasys-cli", "Privasys CLI", []string{"https://privasys.id/device"}, "", []string{"email", "name"}); err != nil {
		t.Fatalf("RegisterWithID with canonical attrs: %v", err)
	}

	if _, err := reg.Register("Open App", []string{"https://app/cb"}, "", nil); err == nil {
		t.Fatal("Register accepted a nil whitelist; want error")
	}
	if _, err := reg.Register("Open App", []string{"https://app/cb"}, "", []string{}); err == nil {
		t.Fatal("Register accepted an empty whitelist; want error")
	}
	if _, err := reg.RegisterWithID("open-id", "Open App", []string{"https://app/cb"}, "", nil); err == nil {
		t.Fatal("RegisterWithID accepted a nil whitelist; want error")
	}
}

// TestSetBilling flags a client as a billable relying party and links its
// billing account + rp_id (defaulting rp_id to the client id), and confirms
// Get round-trips the new columns.
func TestSetBilling(t *testing.T) {
	reg := newTestRegistry(t)
	c, err := reg.Register("Acme RP", []string{"https://acme/cb"}, "", []string{"email", "name"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Default: not billable.
	got, _ := reg.Get(c.ClientID)
	if got.BillableRP {
		t.Fatal("new client should not be billable by default")
	}
	// Flag billable with an explicit rp_id.
	acct := "11111111-1111-1111-1111-111111111111"
	if _, err := reg.SetBilling(c.ClientID, true, acct, "acme.example"); err != nil {
		t.Fatalf("set billing: %v", err)
	}
	got, _ = reg.Get(c.ClientID)
	if !got.BillableRP || got.BillingAccountID != acct || got.RPID != "acme.example" {
		t.Fatalf("billing not persisted: %+v", got)
	}
	// Empty rp_id defaults to the client id.
	if _, err := reg.SetBilling(c.ClientID, true, acct, ""); err != nil {
		t.Fatalf("set billing (default rp_id): %v", err)
	}
	got, _ = reg.Get(c.ClientID)
	if got.RPID != c.ClientID {
		t.Fatalf("rp_id should default to client_id, got %q", got.RPID)
	}
	// Unknown client → error.
	if _, err := reg.SetBilling("nope", true, acct, ""); err == nil {
		t.Fatal("expected error for unknown client")
	}
}

// A client registered by the admin API is a third party and gets its own
// sector; a pre-known client (RegisterWithID) stays in the shared one, and
// moving a client is explicit.
func TestSectors(t *testing.T) {
	reg := newTestRegistry(t)
	third, err := reg.Register("Some Site", []string{"https://site/cb"}, "", []string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := reg.Get(third.ClientID); got.Sector != third.ClientID {
		t.Fatalf("new third-party client sector %q, want its own (%q)", got.Sector, third.ClientID)
	}
	if _, err := reg.RegisterWithID("privasys-platform", "Privasys", []string{"https://p/cb"}, "", []string{"email"}); err != nil {
		t.Fatal(err)
	}
	if reg.SectorOf("privasys-platform") != "" {
		t.Fatal("a pre-known first-party client left the shared sector")
	}
	if err := reg.SetSector("privasys-platform", "privasys"); err != nil {
		t.Fatal(err)
	}
	if reg.SectorOf("privasys-platform") != "privasys" {
		t.Fatal("SetSector did not move the client")
	}
	if err := reg.SetSector("no-such-client", "x"); err == nil {
		t.Fatal("SetSector on an unknown client succeeded")
	}
	if reg.SectorOf("no-such-client") != "" {
		t.Fatal("an unknown client is not in the shared sector")
	}
}
