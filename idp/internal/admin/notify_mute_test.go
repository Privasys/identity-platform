// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/notifymute"
	"github.com/Privasys/idp/internal/store"
)

const mutedApp = "11111111-2222-3333-4444-555555555555"

func relay(t *testing.T, db *store.DB, mutes *notifymute.Service, typ string) (int, string) {
	t.Helper()
	body := `{"sub":"holder","type":"` + typ + `","app_id":"` + mutedApp + `","app_name":"Some App"}`
	req := httptest.NewRequest("POST", "/admin/notify", strings.NewReader(body))
	rec := httptest.NewRecorder()
	// No admin token configured: the dev-mode path, not under test.
	HandleNotify(db, "", nil, mutes)(rec, req)
	var out struct{ Status string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out.Status
}

// Nothing here reaches the push service: a muted notification is answered
// before the push target is looked up, and this holder has no push target, so
// everything else stops at 404.
func TestTheRelayDropsAnAppTheHolderMuted(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	mutes := notifymute.New(db, []byte("0123456789abcdef0123456789abcdef"))

	mute := httptest.NewRequest("PUT", "/wallet/notify-mutes/"+mutedApp, nil)
	mute.SetPathValue("app_id", mutedApp)
	rec := httptest.NewRecorder()
	mutes.HandleMute(func(http.ResponseWriter, *http.Request) string { return "holder" })(rec, mute)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("mute: %d", rec.Code)
	}

	// Answered as a success, so the app has nothing to retry.
	if code, status := relay(t, db, mutes, "app-message"); code != http.StatusOK || status != "muted" {
		t.Fatalf("muted app: %d %q, want 200 muted", code, status)
	}
	// An access request is never silenced: it gets as far as the push target.
	if code, _ := relay(t, db, mutes, "capability-request"); code != http.StatusNotFound {
		t.Fatalf("access request from a muted app: %d, want 404 (no push target)", code)
	}
	// With mutes not wired, nothing is silenced.
	if code, _ := relay(t, db, nil, "app-message"); code != http.StatusNotFound {
		t.Fatalf("no mute service: %d, want 404 (no push target)", code)
	}
}
