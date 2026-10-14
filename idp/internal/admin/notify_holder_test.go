// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An app's subject reaches the holder only through the relationship row the
// holder's sign-in wrote; without one the control plane gets the same answer
// as for a holder with no phone.
func TestNotifyResolvesThroughTheRelationship(t *testing.T) {
	asked := ""
	holders := func(sub, appID string) (string, bool) {
		asked = sub + "@" + appID
		return "", false
	}
	h := HandleNotify(nil, "", nil, nil, holders)
	req := httptest.NewRequest("POST", "/admin/notify",
		strings.NewReader(`{"sub":"sub-gone","type":"share-decision","app_id":"0123456789abcdef0123456789abcdef","payload":{}}`))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a removed holder: %d %s", rec.Code, rec.Body.String())
	}
	if asked != "sub-gone@0123456789abcdef0123456789abcdef" {
		t.Fatalf("resolver asked %q", asked)
	}
}
