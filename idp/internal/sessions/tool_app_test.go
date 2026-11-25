// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessions

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// A tool client (the explorer) reaches apps one at a time: its voucher for an
// app carries the subject that app knows the person by, belongs to the app's
// own client, and is refused without an app.
func TestAToolsVoucherCarriesTheAppsOwnSubject(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	iss, err := tokens.NewIssuer(filepath.Join(dir, "k.pem"), "https://privasys.id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO users (user_id) VALUES ('acct-1')"); err != nil {
		t.Fatal(err)
	}
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	const app = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	s.SetSectorResolver(func(c string) string {
		if c == "tool" || c == "site" {
			return c
		}
		return ""
	})
	s.SetAppsResolver(func(c string) []string {
		if c == "site" {
			return []string{app}
		}
		return nil
	})
	// "site" stands for the app; "tool" may reach any app.
	s.SetToolAppResolver(func(c, appID string) (string, string, bool) {
		if c != "tool" {
			return "", "", false
		}
		if appID == app {
			return "site", "site", true
		}
		return "tool-app\x00tool\x00" + appID, "tool", true
	})
	s.SetWalletSessionResolver(func(token string) (string, bool) { return "acct-1", token == "tok" })
	hw, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hwPub := elliptic.Marshal(elliptic.P256(), hw.PublicKey.X, hw.PublicKey.Y)
	s.SetPasskeysResolver(func(string) ([][]byte, error) { return [][]byte{hwPub}, nil })

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/sessions/encauth", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer wallet:tok")
		rec := httptest.NewRecorder()
		s.HandlePostEncAuth(iss)(rec, req)
		return rec
	}
	allocate := func(appID string) (*httptest.ResponseRecorder, string, string) {
		rec := post(`{"client_id":"tool","app_id":"` + appID + `"}`)
		var alloc struct{ SID, Subject string }
		_ = json.Unmarshal(rec.Body.Bytes(), &alloc)
		return rec, alloc.SID, alloc.Subject
	}
	upload := func(sid, sub, appID string) *httptest.ResponseRecorder {
		now := uint64(time.Now().Unix())
		payload, err := EncAuthCanonicalCBOR(&EncAuth{
			V: 1, Sub: sub, SID: sid,
			WorkloadDigest: bytes32(1), EncMeas: bytes32(2), EncPub: sec1Pub(), QuoteHash: bytes32(3),
			NotBefore: now - 10, NotAfter: now + 3600, HwPub: hwPub,
		})
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(payload)
		r, sv, _ := ecdsa.Sign(rand.Reader, hw, d[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		sv.FillBytes(sig[32:])
		return post(`{"client_id":"tool","app_id":"` + appID + `","host":"app.example","payload":"` +
			base64.RawURLEncoding.EncodeToString(payload) + `","hw_sig":"` + base64.RawURLEncoding.EncodeToString(sig) + `"}`)
	}

	// No app: refused, the subject depends on it.
	if rec, _, _ := allocate(""); rec.Code != http.StatusBadRequest {
		t.Fatalf("allocate without an app: %d %s", rec.Code, rec.Body.String())
	}

	// An app a client stands for: the subject that client gives the person.
	rec, sid, sub := allocate(app)
	if rec.Code != http.StatusOK || sub != iss.SubjectFor("acct-1", "site") {
		t.Fatalf("allocate for a claimed app: %d subject %q", rec.Code, sub)
	}
	if acct, ok := s.HolderOf(sub, "site"); !ok || acct != "acct-1" {
		t.Fatalf("the relationship row belongs to the app's own client: %q %v", acct, ok)
	}
	if rec := upload(sid, sub, app); rec.Code != http.StatusOK {
		t.Fatalf("the tool's voucher for the app: %d %s", rec.Code, rec.Body.String())
	}
	// The tool's own subject, or the account, is not that app's subject.
	if rec := upload(sid, iss.SubjectFor("acct-1", "tool"), app); rec.Code == http.StatusOK {
		t.Fatal("a voucher in the tool's own subject was accepted for the app")
	}
	if rec := upload(sid, "acct-1", app); rec.Code == http.StatusOK {
		t.Fatal("a voucher naming the account was accepted for the app")
	}

	// An app no client claims: the subject of the tool and the app together.
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rec, sid, sub = allocate(other)
	if rec.Code != http.StatusOK || sub != iss.SubjectFor("acct-1", "tool-app\x00tool\x00"+other) {
		t.Fatalf("allocate for an unclaimed app: %d subject %q", rec.Code, sub)
	}
	if rec := upload(sid, sub, other); rec.Code != http.StatusOK {
		t.Fatalf("the tool's voucher for an unclaimed app: %d %s", rec.Code, rec.Body.String())
	}
	// A voucher signed for one app is not accepted for another.
	if rec := upload(sid, sub, app); rec.Code == http.StatusOK {
		t.Fatal("a voucher in one app's subject was accepted for another app")
	}
}
