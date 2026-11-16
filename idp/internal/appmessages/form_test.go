// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package appmessages

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const goodForm = `{"v":1,"id":"req_1","title":"Access to a shared file",` +
	`"blocks":[{"type":"attributes","values":{"name":"Ada","email":"ada@example.org"}},` +
	`{"type":"fields","items":[{"label":"File","value":"Q3 report.pdf"}]},` +
	`{"type":"text","text":"Ada opened your link.\nShe asks to read it."},{"type":"divider"}],` +
	`"actions":[{"id":"approve","kind":"approve"},{"id":"deny","kind":"deny"}],` +
	`"callback":"/api/answer","link":"/#requests"}`

func TestAWellFormedFormPasses(t *testing.T) {
	f, err := ValidateForm(goodForm)
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != "req_1" || f.Digest != FormDigest(goodForm) || strings.Join(f.Actions, ",") != "approve,deny" {
		t.Fatalf("%+v", f)
	}
}

func TestAFormCannotCarryAnythingTheWalletWouldNotDraw(t *testing.T) {
	swap := func(old, new string) string { return strings.Replace(goodForm, old, new, 1) }
	bad := map[string]string{
		"unknown component":        swap(`{"type":"divider"}`, `{"type":"html","html":"<b>x</b>"}`),
		"extra field on a block":   swap(`{"type":"divider"}`, `{"type":"divider","onclick":"x"}`),
		"extra top-level field":    swap(`"v":1,`, `"v":1,"script":"x",`),
		"app-written button":       swap(`{"id":"deny","kind":"deny"}`, `{"id":"deny","kind":"deny","label":"Approve"}`),
		"button kind off the list": swap(`"kind":"deny"`, `"kind":"wipe"`),
		"repeated kind":            swap(`"kind":"deny"`, `"kind":"approve"`),
		"no actions":               swap(`[{"id":"approve","kind":"approve"},{"id":"deny","kind":"deny"}]`, `[]`),
		"callback to another host": swap(`"/api/answer"`, `"//evil.example/x"`),
		"callback as a URL":        swap(`"/api/answer"`, `"https://evil.example/x"`),
		"link not a path":          swap(`"/#requests"`, `"javascript:alert(1)"`),
		"bidi override in title":   swap(`Access to`, "Access ‮to"),
		"zero-width in a value":    swap(`Q3 report`, "Q3​report"),
		"newline in a field":       swap(`Q3 report`, `Q3\nreport`),
		"control char in text":     swap(`She asks`, `She\u0007 asks`),
		"non-canonical attr key":   swap(`"email":`, `"Email Address":`),
		"wrong version":            swap(`"v":1`, `"v":2`),
		"id with a slash":          swap(`"req_1"`, `"req/1"`),
		"too long title":           swap(`Access to a shared file`, strings.Repeat("x", 81)),
	}
	for name, form := range bad {
		if form == goodForm {
			t.Fatalf("%s: the swap did not apply", name)
		}
		if _, err := ValidateForm(form); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseFormPayload(t *testing.T) {
	p, _ := json.Marshal(map[string]string{"kind": "request", "form": goodForm})
	if kind, f, err := ParseFormPayload(p); err != nil || kind != "request" || f.ID != "req_1" {
		t.Fatalf("%v %s %+v", err, kind, f)
	}
	p, _ = json.Marshal(map[string]string{"kind": "reminder", "form": goodForm})
	if _, _, err := ParseFormPayload(p); err == nil {
		t.Fatal("a form is a request or an invitation")
	}
}

func TestATableFromBeforeFormsGainsTheColumns(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The table as idp-v0.3.86 created it, with a row in it.
	if _, err := db.Exec(`CREATE TABLE app_messages (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
		app_id TEXT NOT NULL DEFAULT '', app_name TEXT NOT NULL DEFAULT '', app_host TEXT NOT NULL DEFAULT '',
		kind TEXT NOT NULL, sealed TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
		INSERT INTO app_messages (id, user_id, kind, created_at, expires_at) VALUES ('old', 'alice', 'request', 1, 4102444800);`); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	s, err := open(db, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	got := s.ListFor("alice")
	if len(got) != 1 || got[0].Type != Type {
		t.Fatalf("the old row: %+v", got)
	}
	if _, err := open(db, func() time.Time { return now }); err != nil {
		t.Fatalf("opening twice: %v", err)
	}
}

func TestTakeIsSingleUse(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := testStore(t, &now)
	id, _ := s.Put("alice", Message{Type: FormType, Kind: "invitation", FormID: "f", Actions: []string{"accept"}})
	if _, ok := s.Take("bob", id); ok {
		t.Fatal("bob took alice's form")
	}
	m, ok := s.Take("alice", id)
	if !ok || m.FormID != "f" || len(m.Actions) != 1 {
		t.Fatalf("take: %v %+v", ok, m)
	}
	if _, ok := s.Take("alice", id); ok {
		t.Fatal("taken twice")
	}
}
