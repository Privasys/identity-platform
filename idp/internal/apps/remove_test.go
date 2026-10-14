// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package apps

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/capasks"
	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/sessions"
	"github.com/Privasys/idp/internal/spend"
	"github.com/Privasys/idp/internal/store"
)

// Removing an app ends everything the IdP keeps for the pair: the
// relationship row, the sessions of the client standing for the app, the
// spend consent (reported dead) and the asks waiting. Another app's stay.
func TestRemoveAppEndsThePair(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("INSERT INTO users (user_id) VALUES ('alice')"); err != nil {
		t.Fatal(err)
	}
	reg := clients.NewRegistry(db)
	appA := "0123456789abcdef0123456789abcdef"
	appB := "fedcba9876543210fedcba9876543210"
	if _, err := reg.RegisterWithID("site-a", "Site A", []string{"https://a.example/"}, "", []string{"email"}); err != nil {
		t.Fatal(err)
	}
	if err := reg.SetAppIDs("site-a", []string{appA}); err != nil {
		t.Fatal(err)
	}
	sess, _ := sessions.New(db)
	sp, _ := spend.NewStore(db, sess)
	asks := capasks.New()

	_ = sess.RecordHolder("sub-a", "site-a", "alice")
	a1, _ := sess.Create("", "alice", "site-a", "", time.Hour)
	other, _ := sess.Create("", "alice", "site-b", "", time.Hour)
	if _, err := sp.Grant("alice", "sub-a", appA, "a.example", "A", 100, spend.HandleProof{}); err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Grant("alice", "alice", appB, "b.example", "B", 100, spend.HandleProof{}); err != nil {
		t.Fatal(err)
	}
	asks.Put("alice", "n1", "a.example", appA, "A")
	asks.Put("alice", "n2", "b.example", appB, "B")

	var deadHandles []string
	rm := &Remover{Sessions: sess, Spend: sp, Asks: asks, Clients: reg,
		OnConsentRevoked: func(c *spend.Consent) { deadHandles = append(deadHandles, c.Ledger) }}
	h := HandleRemove(rm, func(w http.ResponseWriter, r *http.Request) string { return "alice" })

	req := httptest.NewRequest(http.MethodDelete, "/wallet/apps/"+appA, nil)
	req.SetPathValue("app_id", appA)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}

	if _, ok := sess.HolderOf("sub-a", "site-a"); ok {
		t.Fatal("relationship row survived")
	}
	if sess.IsActive(a1.SID) || !sess.IsActive(other.SID) {
		t.Fatal("wrong sessions ended")
	}
	if _, err := sp.GetBySubject("sub-a", appA); err == nil {
		t.Fatal("consent for the removed app survived")
	}
	if _, err := sp.GetBySubject("alice", appB); err != nil {
		t.Fatal("another app's consent went with it")
	}
	if len(deadHandles) != 1 || deadHandles[0] == "" {
		t.Fatalf("handles reported dead: %v", deadHandles)
	}
	left := asks.ListFor("alice")
	if len(left) != 1 || left[0].Nonce != "n2" {
		t.Fatalf("asks left: %+v", left)
	}

	// Removing it again, or an app never used, is not an error.
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("second remove: %d", rec.Code)
	}
}
