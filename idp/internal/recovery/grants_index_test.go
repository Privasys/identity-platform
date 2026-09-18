// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func grantsIndexReq(h *Handler, method, body, bearer string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /recovery/grants-index", h.HandlePutGrantsIndex)
	mux.HandleFunc("GET /recovery/grants-index", h.HandleGetGrantsIndex)
	req := httptest.NewRequest(method, "/recovery/grants-index", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The index is written at every approval and read after a recovery. A 404 on
// the read is not an error to the wallet: it is a holder who has never
// approved anything, or a wallet from before this existed.
func TestGrantsIndexRoundTrip(t *testing.T) {
	h, _ := backupTestHandler(t)

	if rec := grantsIndexReq(h, "GET", "", "wallet:good"); rec.Code != http.StatusNotFound {
		t.Fatalf("empty GET: want 404, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := grantsIndexReq(h, "PUT", `{"blob":"AAEC_-12"}`, "wallet:good"); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	rec := grantsIndexReq(h, "GET", "", "wallet:good")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"AAEC_-12"`) {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}

	// Replaced, not appended: the wallet writes the whole index each time.
	if rec := grantsIndexReq(h, "PUT", `{"blob":"ZZZ"}`, "wallet:good"); rec.Code != http.StatusOK {
		t.Fatalf("second PUT: %d %s", rec.Code, rec.Body.String())
	}
	rec = grantsIndexReq(h, "GET", "", "wallet:good")
	if !strings.Contains(rec.Body.String(), `"ZZZ"`) || strings.Contains(rec.Body.String(), "AAEC") {
		t.Fatalf("overwrite did not replace: %s", rec.Body.String())
	}
}

// It is kept apart from the sovereign backup: writing one must never touch
// the other, or an approval could overwrite the holder's root secrets.
func TestGrantsIndexDoesNotTouchTheSovereignBackup(t *testing.T) {
	h, _ := backupTestHandler(t)

	if rec := backupReq(h, "PUT", `{"blob":"ROOTSECRETS"}`, "wallet:good"); rec.Code != http.StatusOK {
		t.Fatalf("backup PUT: %d", rec.Code)
	}
	if rec := grantsIndexReq(h, "PUT", `{"blob":"INDEX"}`, "wallet:good"); rec.Code != http.StatusOK {
		t.Fatalf("index PUT: %d", rec.Code)
	}
	if rec := backupReq(h, "GET", "", "wallet:good"); !strings.Contains(rec.Body.String(), `"ROOTSECRETS"`) {
		t.Fatalf("writing the index changed the backup: %s", rec.Body.String())
	}
}

func TestGrantsIndexNeedsAHolder(t *testing.T) {
	h, _ := backupTestHandler(t)
	for _, c := range []struct{ method, body, bearer string }{
		{"GET", "", ""},
		{"GET", "", "wallet:bad"},
		{"PUT", `{"blob":"AAEC"}`, ""},
		{"PUT", `{"blob":"AAEC"}`, "wallet:bad"},
	} {
		if rec := grantsIndexReq(h, c.method, c.body, c.bearer); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with %q: want 401, got %d", c.method, c.bearer, rec.Code)
		}
	}
}

func TestGrantsIndexRefusesWhatIsNotAnEncryptedBlob(t *testing.T) {
	h, _ := backupTestHandler(t)
	for _, body := range []string{
		`{"blob":""}`,
		`{"blob":"not base64url!"}`,
		`{"blob":"` + strings.Repeat("A", maxGrantsIndexBytes+1) + `"}`,
		`not json`,
	} {
		if rec := grantsIndexReq(h, "PUT", body, "wallet:good"); rec.Code != http.StatusBadRequest {
			t.Errorf("%.40s: want 400, got %d", body, rec.Code)
		}
	}
}
