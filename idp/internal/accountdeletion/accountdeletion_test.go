// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.
package accountdeletion

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/push"
	"github.com/Privasys/idp/internal/store"
)

type fakeCP struct {
	blockers []Blocker
	events   []string
	fail     bool
}

func (f *fakeCP) Check(_ context.Context, sub string) (*CheckResult, error) {
	return &CheckResult{Blockers: f.blockers, Billing: &Billing{PageURL: "https://developer.privasys.org/billing"}}, nil
}

func (f *fakeCP) Event(_ context.Context, kind, sub string, _ time.Time) error {
	if f.fail {
		return context.DeadlineExceeded
	}
	f.events = append(f.events, kind+":"+sub)
	return nil
}

type harness struct {
	svc    *Service
	db     *store.DB
	cp     *fakeCP
	now    time.Time
	pushes []string
}

// Users: "main" (wallet main account, wallet session "w-main"), "pid" (the
// privasys.id identity the page signs in as, bearer "page"), "other" (one
// more identity the wallet marks itself).
func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, u := range []string{"main", "pid", "other"} {
		if err := db.EnsureUser(u); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO credentials (credential_id, user_id, public_key, aaguid, sign_count, attestation_type) VALUES (?, ?, x'00', '', 0, '')`, "cred-"+u, u); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO push_tokens (user_id, device_tag, push_token) VALUES ('main', '', 'tok-main')`); err != nil {
		t.Fatal(err)
	}
	h := &harness{db: db, cp: &fakeCP{}, now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	h.svc = New(Deps{
		DB: db,
		AuthBearer: func(w http.ResponseWriter, r *http.Request) string {
			switch r.Header.Get("Authorization") {
			case "Bearer page":
				return "pid"
			case "Bearer wallet:w-main":
				return "main"
			}
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return ""
		},
		FreshWalletSession: func(token string, _ time.Duration) (string, bool) {
			return "main", token == "w-main"
		},
		VerifyIdentity: func(w http.ResponseWriter, userID, challenge, signature string, msg func([]byte) []byte) bool {
			// The fake signature is the message itself.
			if signature != string(msg([]byte(challenge))) {
				http.Error(w, "bad signature", http.StatusForbidden)
				return false
			}
			return true
		},
		PlatformSubject: func(userID string) string { return "sub-" + userID },
		TombstoneKey:    []byte("k"),
		ControlPlane:    h.cp,
		PageURL:         "https://privasys.id/account/delete",
		ConfirmURL:      "https://privasys.id/account/delete/confirm",
		Push: func(_ context.Context, userID string, m push.Message) error {
			h.pushes = append(h.pushes, userID+":"+m.Data["type"])
			return nil
		},
		Now: func() time.Time { return h.now },
	})
	return h
}

func (h *harness) do(t *testing.T, method, path, auth, body string) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /account-deletion", h.svc.HandleGet)
	mux.HandleFunc("POST /account-deletion", h.svc.HandleConfirm)
	mux.HandleFunc("DELETE /account-deletion", h.svc.HandleCancel)
	mux.HandleFunc("POST /account-deletion/request", h.svc.HandleRequest)
	mux.HandleFunc("GET /account-deletion/request/{id}", h.svc.HandleRequestStatus)
	mux.HandleFunc("POST /account-deletion/identity", h.svc.HandleIdentity)
	mux.HandleFunc("GET /account-deletion/tombstone", h.svc.HandleTombstone)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *harness) schedule(t *testing.T) string {
	t.Helper()
	code, out := h.do(t, "POST", "/account-deletion/request", "Bearer page", "")
	if code != 200 {
		t.Fatalf("request: %d %v", code, out)
	}
	id := out["request_id"].(string)
	if !strings.HasSuffix(out["confirm_url"].(string), "?r="+id) {
		t.Fatalf("confirm_url %v", out["confirm_url"])
	}
	code, out = h.do(t, "POST", "/account-deletion", "Bearer wallet:w-main", `{"request_id":"`+id+`"}`)
	if code != 200 || out["state"] != "pending" {
		t.Fatalf("confirm: %d %v", code, out)
	}
	if code, st := h.do(t, "GET", "/account-deletion/request/"+id, "Bearer page", ""); code != 200 || st["status"] != "scheduled" {
		t.Fatalf("request status: %d %v", code, st)
	}
	return out["delete_at"].(string)
}

func identityBody(userID, action, deleteAt string) string {
	sig := string(Message(userID, []byte("c"), action, deleteAt))
	b, _ := json.Marshal(map[string]string{"user_id": userID, "action": action, "delete_at": deleteAt, "challenge": "c", "signature": sig})
	return string(b)
}

func TestScheduleMarksAndDeletesAfterSevenDays(t *testing.T) {
	h := newHarness(t)
	deleteAt := h.schedule(t)
	if want := FormatTime(h.now.Add(Wait)); deleteAt != want {
		t.Fatalf("delete_at %s, want %s", deleteAt, want)
	}
	if len(h.cp.events) != 1 || h.cp.events[0] != "scheduled:sub-pid" {
		t.Fatalf("control plane events %v", h.cp.events)
	}
	if len(h.pushes) != 1 || h.pushes[0] != "main:account-deletion-scheduled" {
		t.Fatalf("pushes %v", h.pushes)
	}
	// The wallet marks its other identity.
	if code, out := h.do(t, "POST", "/account-deletion/identity", "", identityBody("other", "schedule", deleteAt)); code != 200 {
		t.Fatalf("identity schedule: %d %v", code, out)
	}
	// A wrong signature is a 403 (the wallet tries its next epoch).
	bad := strings.Replace(identityBody("other", "schedule", deleteAt), `"signature":"`, `"signature":"x`, 1)
	if code, _ := h.do(t, "POST", "/account-deletion/identity", "", bad); code != 403 {
		t.Fatalf("bad signature: %d, want 403", code)
	}
	// The banner.
	if code, out := h.do(t, "GET", "/account-deletion", "Bearer wallet:w-main", ""); code != 200 || out["state"] != "pending" || out["delete_at"] != deleteAt {
		t.Fatalf("get: %d %v", code, out)
	}

	// A day before: one reminder, once.
	h.now = h.now.Add(6*24*time.Hour + time.Hour)
	h.svc.Sweep(context.Background())
	h.svc.Sweep(context.Background())
	if n := countSuffix(h.pushes, "account-deletion-reminder"); n != 1 {
		t.Fatalf("reminders %d, want 1 (%v)", n, h.pushes)
	}

	// Day 7: everything goes, tombstones answer.
	h.now = h.now.Add(24 * time.Hour)
	h.svc.Sweep(context.Background())
	for _, u := range []string{"main", "pid", "other"} {
		var n int
		h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE user_id = ?`, u).Scan(&n)
		if n != 0 {
			t.Fatalf("user %s still there", u)
		}
		if code, out := h.do(t, "GET", "/account-deletion/tombstone?credential_id=cred-"+u, "", ""); code != 410 || out["error"] != "account_deleted" {
			t.Fatalf("tombstone %s: %d %v", u, code, out)
		}
	}
	if code, _ := h.do(t, "GET", "/account-deletion/tombstone?credential_id=never", "", ""); code != 404 {
		t.Fatalf("unknown credential: %d, want 404", code)
	}
	if countSuffix(h.pushes, "account-deleted") != 1 {
		t.Fatalf("account-deleted push missing: %v", h.pushes)
	}
	if h.cp.events[len(h.cp.events)-1] != "deleted:sub-pid" {
		t.Fatalf("control plane not told deleted: %v", h.cp.events)
	}
}

func TestControlPlaneDownDefersDeletion(t *testing.T) {
	h := newHarness(t)
	h.schedule(t)
	h.cp.fail = true
	h.now = h.now.Add(Wait + time.Minute)
	h.svc.Sweep(context.Background())
	var n int
	h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE user_id = 'pid'`).Scan(&n)
	if n != 1 {
		t.Fatal("the identity behind the control-plane account went before the control plane answered")
	}
	h.cp.fail = false
	h.svc.Sweep(context.Background())
	h.db.QueryRow(`SELECT COUNT(*) FROM users WHERE user_id = 'pid'`).Scan(&n)
	if n != 0 {
		t.Fatal("not deleted on retry")
	}
}

func TestCancelAndRecovery(t *testing.T) {
	h := newHarness(t)
	deleteAt := h.schedule(t)
	h.do(t, "POST", "/account-deletion/identity", "", identityBody("other", "schedule", deleteAt))

	// The wallet cancels: main account, then each identity (delete_at "").
	if code, out := h.do(t, "DELETE", "/account-deletion", "Bearer wallet:w-main", ""); code != 200 || out["state"] != "none" {
		t.Fatalf("cancel: %d %v", code, out)
	}
	for _, u := range []string{"pid", "other", "other"} { // twice: idempotent
		if code, out := h.do(t, "POST", "/account-deletion/identity", "", identityBody(u, "cancel", "")); code != 200 {
			t.Fatalf("cancel %s: %d %v", u, code, out)
		}
	}
	if countSuffix(h.pushes, "account-deletion-cancelled") != 1 || h.cp.events[len(h.cp.events)-1] != "cancelled:sub-pid" {
		t.Fatalf("pushes %v, events %v", h.pushes, h.cp.events)
	}
	h.now = h.now.Add(Wait + time.Hour)
	h.svc.Sweep(context.Background())
	var n int
	h.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if n != 3 {
		t.Fatalf("%d users left after a cancelled deletion, want 3", n)
	}

	// A phrase recovery cancels the main account's mark.
	h.now = time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	h.schedule(t)
	h.svc.CancelForRecovery("main")
	if d, _ := h.db.GetAccountDeletion("main"); d != nil {
		t.Fatal("recovery did not cancel the main account's mark")
	}
}

func TestBlockedAndStaleConfirm(t *testing.T) {
	h := newHarness(t)
	h.cp.blockers = []Blocker{{Kind: "apps", Count: 2, Label: "2 apps"}}
	if code, out := h.do(t, "POST", "/account-deletion/request", "Bearer page", ""); code != 409 || out["error"] != "blocked" {
		t.Fatalf("blocked request: %d %v", code, out)
	}
	h.cp.blockers = nil
	_, out := h.do(t, "POST", "/account-deletion/request", "Bearer page", "")
	id := out["request_id"].(string)
	// A stale wallet session cannot confirm.
	if code, _ := h.do(t, "POST", "/account-deletion", "Bearer wallet:old", `{"request_id":"`+id+`"}`); code != 401 {
		t.Fatalf("stale session: %d, want 401", code)
	}
	// An expired request cannot be confirmed.
	h.now = h.now.Add(requestTTL + time.Second)
	if code, _ := h.do(t, "POST", "/account-deletion", "Bearer wallet:w-main", `{"request_id":"`+id+`"}`); code != 404 {
		t.Fatalf("expired request: %d, want 404", code)
	}
	// A schedule date outside the window is refused.
	if code, _ := h.do(t, "POST", "/account-deletion/identity", "", identityBody("other", "schedule", FormatTime(h.now.Add(30*24*time.Hour)))); code != 400 {
		t.Fatalf("far date: %d, want 400", code)
	}
}

func countSuffix(xs []string, suffix string) int {
	n := 0
	for _, x := range xs {
		if strings.HasSuffix(x, ":"+suffix) {
			n++
		}
	}
	return n
}
