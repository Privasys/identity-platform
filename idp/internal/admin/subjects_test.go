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

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

func TestSubjectEndpoints(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	iss, _ := tokens.NewIssuer(filepath.Join(dir, "k.pem"), "https://privasys.id")
	iss.SetSubjectStore(db)

	post := func(h http.HandlerFunc, body, token string) (int, map[string]map[string]string) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		var out map[string]map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	forH := HandleSubjectsFor(iss, "admin")
	resolveH := HandleResolveSubjects(db, "admin")

	if code, _ := post(forH, `{"client_id":"drive","accounts":["acct-1"]}`, ""); code != http.StatusUnauthorized {
		t.Fatalf("no admin token: %d", code)
	}
	code, out := post(forH, `{"client_id":"drive","accounts":["acct-1","acct-2"]}`, "admin")
	if code != http.StatusOK || out["subjects"]["acct-1"] != iss.SubjectFor("acct-1", "drive") {
		t.Fatalf("subjects for: %d %v", code, out)
	}
	sub := out["subjects"]["acct-1"]
	code, res := post(resolveH, `{"subs":["`+sub+`","acct-9"]}`, "admin")
	if code != http.StatusOK || res["accounts"][sub] != "acct-1" {
		t.Fatalf("resolve: %d %v", code, res)
	}
	if _, has := res["accounts"]["acct-9"]; has {
		t.Fatal("an unknown subject was resolved to something")
	}
}
