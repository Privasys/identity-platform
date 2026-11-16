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

	"github.com/Privasys/idp/internal/appmessages"
	"github.com/Privasys/idp/internal/store"
)

func relayMessage(t *testing.T, db *store.DB, msgs *appmessages.Store, payload string) int {
	t.Helper()
	body := `{"sub":"holder","type":"app-message","app_id":"` + mutedApp +
		`","app_name":"Some App","app_host":"app.example.org","payload":` + payload + `}`
	rec := httptest.NewRecorder()
	HandleNotify(db, "", nil, nil, nil, msgs)(rec, httptest.NewRequest("POST", "/admin/notify", strings.NewReader(body)))
	return rec.Code
}

func TestAnAppMessageWaitingOnTheHolderIsKeptEvenWithoutAPushTarget(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	msgs, err := appmessages.New(db.DB)
	if err != nil {
		t.Fatalf("app messages: %v", err)
	}

	// No push target: 404 to the control plane, but the request is listed,
	// with the host the platform named and no payload (nothing to seal to).
	if code := relayMessage(t, db, msgs, `{"kind":"request","path":"/requests/1"}`); code != http.StatusNotFound {
		t.Fatalf("request: %d, want 404 (no push target)", code)
	}
	got := msgs.ListFor("holder")
	if len(got) != 1 || got[0].Kind != "request" || got[0].AppHost != "app.example.org" || got[0].Sealed != "" {
		t.Fatalf("listed: %+v", got)
	}

	// A response does not wait on the holder: not listed.
	relayMessage(t, db, msgs, `{"kind":"response"}`)
	if n := len(msgs.ListFor("holder")); n != 1 {
		t.Fatalf("a response was listed: %d", n)
	}
}

func TestAnAppMessageMustBeWellFormed(t *testing.T) {
	for _, payload := range []string{
		`null`,
		`{"path":"/x"}`,
		`{"kind":"request","path":"https://evil.example/x"}`,
		`{"kind":"request","path":"//evil.example/x"}`,
		`{"kind":"request","presented":"Ada"}`,
	} {
		if code := relayMessage(t, nil, nil, payload); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", payload, code)
		}
	}
}

const relayForm = `{"v":1,"id":"req_9","title":"Join a room",` +
	`"blocks":[{"type":"text","text":"You are invited."}],` +
	`"actions":[{"id":"accept","kind":"accept"},{"id":"decline","kind":"decline"}],"callback":"/answer"}`

func relayFormTo(t *testing.T, db *store.DB, msgs *appmessages.Store, platformHost string) int {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"kind": "invitation", "form": relayForm})
	body, _ := json.Marshal(map[string]any{
		"sub": "holder", "type": "app-form", "app_id": mutedApp, "app_name": "Some App",
		"app_host": "app.example.org", "app_platform_host": platformHost, "app_slug": "app", "payload": json.RawMessage(payload),
	})
	rec := httptest.NewRecorder()
	HandleNotify(db, "", nil, nil, nil, msgs)(rec, httptest.NewRequest("POST", "/admin/notify", strings.NewReader(string(body))))
	return rec.Code
}

func TestAFormIsKeptWithWhatItsAnswerNeeds(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	msgs, _ := appmessages.New(db.DB)

	// Without the attestable host there is nowhere safe to send the answer.
	if code := relayFormTo(t, db, msgs, ""); code != http.StatusBadRequest {
		t.Fatalf("no platform host: %d", code)
	}
	if code := relayFormTo(t, db, msgs, "app.apps.test.privasys.org"); code != http.StatusNotFound {
		t.Fatalf("form: %d, want 404 (no push target)", code)
	}
	got := msgs.ListFor("holder")
	if len(got) != 1 {
		t.Fatalf("listed: %+v", got)
	}
	m := got[0]
	if m.Type != "app-form" || m.FormID != "req_9" || m.FormDigest != appmessages.FormDigest(relayForm) ||
		strings.Join(m.Actions, ",") != "accept,decline" || m.PlatformHost != "app.apps.test.privasys.org" || m.AppSub != "holder" {
		t.Fatalf("row: %+v", m)
	}
}
