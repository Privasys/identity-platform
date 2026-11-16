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

const relayApproval = `{"v":1,"id":"dec_9","title":"Record full registration",` +
	`"lines":[{"label":"Dataset","value":"Coastal readings"}],` +
	`"act_digest":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",` +
	`"assurance":"device","callback":"/approvals/answer","ttl":120}`

func relayApprovalTo(t *testing.T, db *store.DB, msgs *appmessages.Store, approval, platformHost string) int {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"approval": approval})
	body, _ := json.Marshal(map[string]any{
		"sub": "holder", "type": "approval", "app_id": mutedApp, "app_name": "Some App",
		"app_host": "app.example.org", "app_platform_host": platformHost, "app_slug": "app", "payload": json.RawMessage(payload),
	})
	rec := httptest.NewRecorder()
	HandleNotify(db, "", nil, nil, nil, msgs)(rec, httptest.NewRequest("POST", "/admin/notify", strings.NewReader(string(body))))
	return rec.Code
}

func TestAnApprovalIsKeptWithWhatItsAnswerNeeds(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	msgs, _ := appmessages.New(db.DB)

	if code := relayApprovalTo(t, db, msgs, relayApproval, ""); code != http.StatusBadRequest {
		t.Fatalf("no platform host: %d", code)
	}
	if code := relayApprovalTo(t, db, msgs, `{"v":1}`, "app.apps.test.privasys.org"); code != http.StatusBadRequest {
		t.Fatalf("malformed: %d", code)
	}
	presence := strings.Replace(relayApproval, `"device"`, `"gov-presence"`, 1)
	if code := relayApprovalTo(t, db, msgs, presence, "app.apps.test.privasys.org"); code != http.StatusBadRequest {
		t.Fatalf("gov-presence before it is built: %d", code)
	}
	if code := relayApprovalTo(t, db, msgs, relayApproval, "app.apps.test.privasys.org"); code != http.StatusNotFound {
		t.Fatalf("approval: %d, want 404 (no push target)", code)
	}
	got := msgs.ListFor("holder")
	if len(got) != 1 {
		t.Fatalf("listed: %+v", got)
	}
	m := got[0]
	if m.Type != "approval" || m.FormID != "dec_9" || m.FormDigest != appmessages.FormDigest(relayApproval) ||
		strings.Join(m.Actions, ",") != "approve,decline" || m.Assurance != "device" || m.AppSub != "holder" ||
		m.PlatformHost != "app.apps.test.privasys.org" || m.ExpiresAt-m.CreatedAt != 120 {
		t.Fatalf("row: %+v", m)
	}
}
