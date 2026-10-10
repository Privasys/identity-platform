// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/store"
)

func guardianTest(t *testing.T) (*store.DB, *http.ServeMux) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, u := range []string{"holder", "g1", "g2", "stranger"} {
		if _, err := db.Exec("INSERT INTO users (user_id) VALUES (?)", u); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []string{"g1", "g2"} {
		if _, err := db.Exec(
			"INSERT INTO guardians (user_id, guardian_id, status, threshold) VALUES ('holder', ?, 'accepted', 5)", g,
		); err != nil {
			t.Fatal(err)
		}
	}
	h := NewHandler(db, nil, nil)
	h.SetWalletSessionResolver(func(token string) (string, bool) { return token, token != "" })
	mux := http.NewServeMux()
	mux.HandleFunc("POST /recovery/approve", h.HandleApproveRecovery)
	return db, mux
}

func approve(mux *http.ServeMux, guardian, requestID string) int {
	req := httptest.NewRequest("POST", "/recovery/approve", strings.NewReader(`{"request_id":"`+requestID+`","approved":true}`))
	req.Header.Set("Authorization", "Bearer wallet:"+guardian)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

func approvals(t *testing.T, db *store.DB, requestID string) int {
	t.Helper()
	rr, err := db.GetRecoveryRequest(requestID)
	if err != nil {
		t.Fatal(err)
	}
	return rr.GuardiansApproved
}

func TestOnlyAGuardianCountsAndOnlyOnce(t *testing.T) {
	db, mux := guardianTest(t)
	if err := db.CreateRecoveryRequest("req", "holder", 2, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if code := approve(mux, "stranger", "req"); code != http.StatusForbidden {
		t.Fatalf("a stranger's approval: %d, want 403", code)
	}
	if code := approve(mux, "g1", "req"); code != http.StatusOK {
		t.Fatalf("guardian approval: %d", code)
	}
	if code := approve(mux, "g1", "req"); code != http.StatusOK {
		t.Fatalf("repeat approval: %d", code)
	}
	if n := approvals(t, db, "req"); n != 1 {
		t.Fatalf("approvals counted: %d, want 1 (one guardian, twice)", n)
	}
	approve(mux, "g2", "req")
	if n := approvals(t, db, "req"); n != 2 {
		t.Fatalf("approvals counted: %d, want 2", n)
	}
}

func TestAClosedRequestTakesNoApprovals(t *testing.T) {
	db, mux := guardianTest(t)
	if err := db.CreateRecoveryRequest("old", "holder", 2, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if code := approve(mux, "g1", "old"); code != http.StatusForbidden {
		t.Fatalf("approval of an expired request: %d, want 403", code)
	}
}

func TestTheThresholdNeverExceedsTheGuardians(t *testing.T) {
	db, _ := guardianTest(t)
	count, threshold, err := db.GetAcceptedGuardianCount("holder")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || threshold != 2 {
		t.Fatalf("count %d threshold %d, want 2 and 2 (5 capped to the guardians there are)", count, threshold)
	}
}

func TestTheInvitePageOpensTheWalletAndRefusesJunk(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /guardians/invite", h.HandleGuardianInvitePage)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/guardians/invite?token=0123456789abcdef0123456789abcdef", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(),
		`href="privasys-wallet://account-recovery?invite=0123456789abcdef0123456789abcdef"`) {
		t.Fatalf("page: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the page may be cached with a capability in it")
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", `/guardians/invite?token="><script>`, nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("junk token: %d, want 400", rec.Code)
	}
}
