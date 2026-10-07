// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/store"
)

const (
	driveApp = "11111111-2222-3333-4444-555555555555"
	otherApp = "99999999-8888-7777-6666-555555555555"
)

func notifyTo(t *testing.T, db *store.DB, sub, appID string) int {
	t.Helper()
	body := `{"sub":"` + sub + `","type":"share-request","app_id":"` + appID + `","app_name":"Drive"}`
	req := httptest.NewRequest("POST", "/admin/notify", strings.NewReader(body))
	rec := httptest.NewRecorder()
	// No admin token configured: the dev-mode path, which is not under test.
	HandleNotify(db, "", nil)(rec, req)
	return rec.Code
}

// The notification refused here never reaches the push service: every case
// either stops at the audience check or at "no push target", so no test sends
// anything to Expo.
func TestAnAppReachesOnlyIdentitiesThatSignedInToIt(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.AddNotifyAudience("holder", driveApp); err != nil {
		t.Fatalf("record: %v", err)
	}
	// Recording twice is the same as once.
	if err := db.AddNotifyAudience("holder", driveApp); err != nil {
		t.Fatalf("record again: %v", err)
	}

	prev := enforceNotifyAudience
	t.Cleanup(func() { enforceNotifyAudience = prev })

	enforceNotifyAudience = true
	if code := notifyTo(t, db, "holder", otherApp); code != http.StatusForbidden {
		t.Fatalf("an app the holder never signed in to: %d, want 403", code)
	}
	if code := notifyTo(t, db, "someone-else", driveApp); code != http.StatusForbidden {
		t.Fatalf("an identity that never signed in to this app: %d, want 403", code)
	}
	if code := notifyTo(t, db, "holder", ""); code != http.StatusForbidden {
		t.Fatalf("no app id at all: %d, want 403", code)
	}
	// Past the check, this test identity has no push token, which is the
	// answer that proves the check let it through.
	if code := notifyTo(t, db, "holder", driveApp); code != http.StatusNotFound {
		t.Fatalf("the app the holder signed in to: %d, want 404 (no push target)", code)
	}

	// Observing, nothing is refused yet: the same unknown app gets as far as
	// the push target.
	enforceNotifyAudience = false
	if code := notifyTo(t, db, "holder", otherApp); code != http.StatusNotFound {
		t.Fatalf("observe mode refused: %d, want 404 (no push target)", code)
	}
}
