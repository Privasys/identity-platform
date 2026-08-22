// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/store"
)

func backupTestHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	const userID = "user-backup-test"
	if _, err := db.Exec("INSERT INTO users (user_id) VALUES (?)", userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	h := NewHandler(db, nil, nil)
	h.SetWalletSessionResolver(func(token string) (string, bool) {
		if token == "good" {
			return userID, true
		}
		return "", false
	})
	return h, userID
}

func backupReq(h *Handler, method, body, bearer string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /recovery/backup", h.HandlePutBackup)
	mux.HandleFunc("GET /recovery/backup", h.HandleGetBackup)
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, "/recovery/backup", rdr)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestSovereignBackupRoundTrip(t *testing.T) {
	h, _ := backupTestHandler(t)

	// No blob yet: 404.
	if rec := backupReq(h, "GET", "", "wallet:good"); rec.Code != http.StatusNotFound {
		t.Fatalf("empty GET: want 404, got %d %s", rec.Code, rec.Body.String())
	}

	// Store, fetch back, then overwrite.
	if rec := backupReq(h, "PUT", `{"blob":"AAEC_-12"}`, "wallet:good"); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	rec := backupReq(h, "GET", "", "wallet:good")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"AAEC_-12"`) {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if rec := backupReq(h, "PUT", `{"blob":"Zm9vYmFy"}`, "wallet:good"); rec.Code != http.StatusOK {
		t.Fatalf("overwrite PUT: %d %s", rec.Code, rec.Body.String())
	}
	rec = backupReq(h, "GET", "", "wallet:good")
	if !strings.Contains(rec.Body.String(), `"Zm9vYmFy"`) {
		t.Fatalf("overwrite GET: %s", rec.Body.String())
	}
}

func TestSovereignBackupValidation(t *testing.T) {
	h, _ := backupTestHandler(t)

	// Unauthenticated and bad-session callers are refused.
	if rec := backupReq(h, "PUT", `{"blob":"Zm9v"}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer: want 401, got %d", rec.Code)
	}
	if rec := backupReq(h, "GET", "", "wallet:bad"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad session: want 401, got %d", rec.Code)
	}

	// Shape violations: empty, non-base64url, oversized.
	for _, body := range []string{
		`{"blob":""}`,
		`{"blob":"not base64url!"}`,
		`{"blob":"` + strings.Repeat("A", maxBackupBlobBytes+1) + `"}`,
		`not json`,
	} {
		if rec := backupReq(h, "PUT", body, "wallet:good"); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %.20q: want 400, got %d", body, rec.Code)
		}
	}
}
