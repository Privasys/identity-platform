// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package clients

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

// Every client created through the admin API gets its own subjects, with or
// without a chosen id; a pre-known first-party client seeded in code
// (RegisterWithID) stays in the legacy shared mode until moved.
func TestSubjectModes(t *testing.T) {
	reg := newTestRegistry(t)
	third, err := reg.Register("Some Site", []string{"https://site/cb"}, "", []string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	if reg.SectorOf(third.ClientID) != third.ClientID {
		t.Fatal("a new client does not have its own subjects")
	}
	if _, err := reg.RegisterWithID("privasys-cli", "CLI", []string{"https://p/cb"}, "", []string{"email"}); err != nil {
		t.Fatal(err)
	}
	if reg.SectorOf("privasys-cli") != "" {
		t.Fatal("a seeded first-party client left the legacy shared mode")
	}

	h := HandleRegister(reg, "admin")
	req := httptest.NewRequest("POST", "/clients", strings.NewReader(
		`{"client_id":"named-site","client_name":"Named","redirect_uris":["https://n/cb"],"required_attributes":["email"]}`))
	req.Header.Set("Authorization", "Bearer admin")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusCreated || reg.SectorOf("named-site") != "named-site" {
		t.Fatalf("admin-registered client with an id: %d, sector %q", rec.Code, reg.SectorOf("named-site"))
	}

	mode := HandleSetSubjectMode(reg, "admin")
	set := func(id, body string) int {
		req := httptest.NewRequest("POST", "/clients/"+id+"/subject", strings.NewReader(body))
		req.SetPathValue("id", id)
		req.Header.Set("Authorization", "Bearer admin")
		rec := httptest.NewRecorder()
		mode(rec, req)
		return rec.Code
	}
	if set("privasys-cli", `{"mode":"own"}`) != http.StatusOK || reg.SectorOf("privasys-cli") != "privasys-cli" {
		t.Fatal("moving a client to its own subjects failed")
	}
	if set("privasys-cli", `{"mode":"team-a"}`) != http.StatusBadRequest {
		t.Fatal("a named group was accepted; clients never share subjects")
	}
	if set("nobody", `{"mode":"own"}`) != http.StatusNotFound {
		t.Fatal("an unknown client was moved")
	}
}
