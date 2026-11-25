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

// Widening a client's whitelist changes the whitelist and nothing else: its
// name, redirect URIs and secret survive, and a non-canonical key is refused.
func TestSetRequiredAttributes(t *testing.T) {
	reg := newTestRegistry(t)
	if _, err := reg.RegisterWithID("portal", "Portal", []string{"https://portal/cb"}, "s3cret", []string{"name"}); err != nil {
		t.Fatal(err)
	}
	c, err := reg.SetRequiredAttributes("portal", []string{"name", "given_name_id"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.RequiredAttributes) != 2 || c.RequiredAttributes[1] != "given_name_id" {
		t.Fatalf("required_attributes = %v", c.RequiredAttributes)
	}
	if c.ClientName != "Portal" || len(c.RedirectURIs) != 1 {
		t.Fatalf("registration changed: %+v", c)
	}
	if ok, _ := reg.VerifySecret("portal", "s3cret"); !ok {
		t.Fatal("the secret did not survive")
	}
	if _, err := reg.SetRequiredAttributes("portal", []string{"not_a_key"}); err == nil {
		t.Fatal("a non-canonical key was accepted")
	}
	if _, err := reg.SetRequiredAttributes("nobody", []string{"name"}); err == nil {
		t.Fatal("an unknown client was updated")
	}
}

// A client's users may be restricted to named external identity providers;
// the restriction is operator-set, normalised, and lifted by an empty list.
func TestSocialProviders_SetAndRead(t *testing.T) {
	reg := newTestRegistry(t)
	c, err := reg.Register("Workplace app", []string{"https://app.example/cb"}, "", []string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	if got := reg.SocialProvidersOf(c.ClientID); got != nil {
		t.Fatalf("a new client restricts nothing, got %v", got)
	}
	clean, err := reg.SetSocialProviders(c.ClientID, []string{" Microsoft ", "google", "microsoft"})
	if err != nil {
		t.Fatal(err)
	}
	if len(clean) != 2 || clean[0] != "microsoft" || clean[1] != "google" {
		t.Fatalf("normalised list = %v", clean)
	}
	if got := reg.SocialProvidersOf(c.ClientID); len(got) != 2 || got[0] != "microsoft" {
		t.Fatalf("stored list = %v", got)
	}
	full, err := reg.Get(c.ClientID)
	if err != nil || len(full.SocialProviders) != 2 {
		t.Fatalf("Get carries the list: %+v %v", full, err)
	}
	if _, err := reg.SetSocialProviders(c.ClientID, []string{"Not A Provider!"}); err == nil {
		t.Fatal("an invalid provider name must be refused")
	}
	if _, err := reg.SetSocialProviders(c.ClientID, nil); err != nil {
		t.Fatal(err)
	}
	if got := reg.SocialProvidersOf(c.ClientID); got != nil {
		t.Fatalf("an empty list lifts the restriction, got %v", got)
	}
	if _, err := reg.SetSocialProviders("no-such-client", []string{"github"}); err == nil {
		t.Fatal("an unknown client must be refused")
	}
	if got := reg.SocialProvidersOf("no-such-client"); got != nil {
		t.Fatalf("an unknown client restricts nothing here (it is refused elsewhere), got %v", got)
	}
}

// A client accepts the pages of the apps it stands for, and of no other app.
func TestAppOrigins(t *testing.T) {
	reg := newTestRegistry(t)
	c, err := reg.Register("app", []string{"https://rp.example/cb"}, "", []string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := reg.Register("other", []string{"https://other.example/cb"}, "", []string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	const app = "590ebdc3-1b63-401f-bbb8-22d5f3886c5e"
	const stranger = "11111111-2222-3333-4444-555555555555"
	accepts := func(clientID, origin string) bool {
		t.Helper()
		got, err := reg.Get(clientID)
		if err != nil {
			t.Fatal(err)
		}
		return got.AcceptsOrigin(origin)
	}

	// Reported before the client names the app: nothing follows yet.
	if _, err := reg.SetAppOrigins(app, []string{"https://App.apps.example/", "https://custom.example", "https://custom.example"}); err != nil {
		t.Fatal(err)
	}
	if got := reg.AppOriginsOf(app); len(got) != 2 || got[0] != "https://app.apps.example" || got[1] != "https://custom.example" {
		t.Fatalf("origins are normalised and listed once, got %v", got)
	}
	if accepts(c.ClientID, "https://custom.example") {
		t.Fatal("an app's origin was accepted by a client that does not stand for it")
	}
	if _, err := reg.SetAppOrigins(stranger, []string{"https://stranger.example"}); err != nil {
		t.Fatal(err)
	}

	if err := reg.SetAppIDs(c.ClientID, []string{app}); err != nil {
		t.Fatal(err)
	}
	for origin, want := range map[string]bool{
		"https://app.apps.example": true,
		"https://custom.example":   true,
		"https://rp.example":       true,
		"https://stranger.example": false,
	} {
		if got := accepts(c.ClientID, origin); got != want {
			t.Errorf("%q: %v, want %v", origin, got, want)
		}
	}
	if accepts(other.ClientID, "https://custom.example") {
		t.Fatal("another client accepted the app's origin")
	}

	// The list is replaced, so a removed domain stops being accepted.
	if _, err := reg.SetAppOrigins(app, []string{"https://app.apps.example"}); err != nil {
		t.Fatal(err)
	}
	if accepts(c.ClientID, "https://custom.example") {
		t.Fatal("a removed origin is still accepted")
	}
	if _, err := reg.SetAppOrigins(app, nil); err != nil {
		t.Fatal(err)
	}
	if accepts(c.ClientID, "https://app.apps.example") || reg.AppOriginsOf(app) != nil {
		t.Fatal("an empty list must forget the app")
	}

	for _, bad := range [][]string{{"http://plain.example"}, {"not a url"}, make([]string, maxAppOrigins+1)} {
		if _, err := reg.SetAppOrigins(app, bad); err == nil {
			t.Errorf("%v: accepted", bad)
		}
	}
	if _, err := reg.SetAppOrigins("not-an-app", []string{"https://a.example"}); err == nil {
		t.Fatal("a malformed app id was accepted")
	}
}

func TestAcceptsOrigin(t *testing.T) {
	c := &Client{
		RedirectURIs:   []string{"https://App.example/callback", "http://localhost:4200/cb", "http://evil.example/cb"},
		AllowedOrigins: []string{"https://console.example"},
	}
	for origin, want := range map[string]bool{
		"https://app.example":      true,
		"https://console.example":  true,
		"http://localhost:4200":    true,
		"https://app.example:8443": false,
		"http://app.example":       false,
		"http://evil.example":      false,
		"https://app.example.evil": false,
		"https://evil.example":     false,
		"null":                     false,
		"":                         false,
		"https://user@app.example": false,
	} {
		if got := c.AcceptsOrigin(origin); got != want {
			t.Errorf("%q: %v, want %v", origin, got, want)
		}
	}
}

// A tool client is an own-subject, non-platform client an operator marks;
// for an app it uses the sector of the app's own client, else one of the
// tool and the app together.
func TestToolClientsAndTheSubjectTheyUseAtAnApp(t *testing.T) {
	reg := newTestRegistry(t)
	for _, id := range []string{"tool", "site", "platform-client", "legacy"} {
		if _, err := reg.RegisterWithID(id, id, nil, "", []string{"email"}); err != nil {
			t.Fatal(err)
		}
	}
	const app = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_ = reg.SetSector("tool", "tool")
	_ = reg.SetSector("site", "site")
	_ = reg.SetSector("platform-client", "platform-client")
	_ = reg.SetPlatform("platform-client", true)
	if err := reg.SetAppIDs("site", []string{app}); err != nil {
		t.Fatal(err)
	}

	if err := reg.SetAnyAppAudience("platform-client", true); err == nil {
		t.Fatal("a platform client was made a tool client")
	}
	if err := reg.SetAnyAppAudience("legacy", true); err == nil {
		t.Fatal("a shared-subject client was made a tool client")
	}
	if reg.AnyAppAudience("tool") {
		t.Fatal("a client is a tool client before an operator says so")
	}
	if err := reg.SetAnyAppAudience("tool", true); err != nil || !reg.AnyAppAudience("tool") {
		t.Fatalf("marking a tool client: %v", err)
	}
	// Moved to the shared subject later, it stops being one.
	_ = reg.SetSector("tool", "")
	if reg.AnyAppAudience("tool") {
		t.Fatal("a shared-subject client still counts as a tool client")
	}
	_ = reg.SetSector("tool", "tool")

	if sector, holder := reg.AppSubjectSector(app, "tool"); sector != "site" || holder != "site" {
		t.Fatalf("a claimed app: sector %q holder %q", sector, holder)
	}
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if sector, holder := reg.AppSubjectSector(other, "tool"); sector != "tool-app\x00tool\x00"+other || holder != "tool" {
		t.Fatalf("an unclaimed app: sector %q holder %q", sector, holder)
	}
}
