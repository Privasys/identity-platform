// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package spend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// A consent is addressed by the subject the app sees; its ledger handle is
// what the platform debits by, bound to the account by a statement the IdP
// signs and the holder co-signs, delivered through the outbox.
func TestConsentHandleAndStatement(t *testing.T) {
	f := newFixture(t)

	// A control plane that records what it is told.
	var mu sync.Mutex
	var told []map[string]any
	fail := false
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/internal/ledger-handles" || r.Header.Get("Authorization") != "Bearer mgmt" {
			http.NotFound(w, r)
			return
		}
		if fail {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		var body struct{ Statement string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		parsed, _, err := jwt.NewParser().ParseUnverified(body.Statement, jwt.MapClaims{})
		if err != nil {
			t.Errorf("statement: %v", err)
			return
		}
		if typ, _ := parsed.Header["typ"].(string); typ != "ledger-handle+jwt" {
			t.Errorf("statement typ %q", typ)
		}
		mu.Lock()
		told = append(told, parsed.Claims.(jwt.MapClaims))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(cp.Close)
	ob, err := NewOutbox(f.store.db, []OutboxTarget{{URL: cp.URL, Token: "mgmt"}, {URL: "", Token: ""}}, cp.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.h.outbox = ob
	f.h.subjectFor = func(userID, _ string) string { return "sub:" + userID }

	// The wallet mints the handle and signs handle‖app‖cap with the
	// identity's passkey, which the IdP looks up from the wallet session.
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	handle := NewHandle()
	sign := func(h string, cap int64) string {
		d := sha256.Sum256([]byte(h + "\x00" + f.appID + "\x00" + strconv.FormatInt(cap, 10)))
		r, s, _ := ecdsa.Sign(rand.Reader, holder, d[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return base64.RawURLEncoding.EncodeToString(sig)
	}
	pub := base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), holder.PublicKey.X, holder.PublicKey.Y))
	grant := func(body string) (int, map[string]any) {
		r := httptest.NewRequest(http.MethodPost, "/spend/consents", strings.NewReader(body))
		r.Header.Set("X-Test-User", "user-1")
		w := httptest.NewRecorder()
		f.h.HandleGrantConsent(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	signed := func(h string, cap int64) string {
		return `{"app_id":"` + f.appID + `","cap":100,"ledger_handle":"` + h + `","wallet_sig":"` + sign(h, cap) + `"}`
	}

	// Without a wallet session there is no passkey to check the binding by.
	if code, _ := grant(signed(handle, 100)); code != http.StatusBadRequest {
		t.Fatalf("a binding without a wallet session accepted: %d", code)
	}
	// A key the wallet names is refused outright: the passkey is looked up.
	f.passkey = elliptic.Marshal(elliptic.P256(), holder.PublicKey.X, holder.PublicKey.Y)
	if code, _ := grant(`{"app_id":"` + f.appID + `","cap":100,"ledger_handle":"` + handle + `","wallet_sig":"` + sign(handle, 100) + `","holder_pub":"` + pub + `"}`); code != http.StatusBadRequest {
		t.Fatalf("a wallet-named holder key accepted: %d", code)
	}
	// A signature over something else is refused; a bad handle too.
	if code, _ := grant(signed(handle, 99)); code != http.StatusBadRequest {
		t.Fatalf("mismatched signature accepted: %d", code)
	}
	if code, _ := grant(`{"app_id":"` + f.appID + `","cap":100,"ledger_handle":"short"}`); code != http.StatusBadRequest {
		t.Fatalf("bad handle accepted: %d", code)
	}
	// A signature by another passkey than the session's.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.passkey = elliptic.Marshal(elliptic.P256(), other.PublicKey.X, other.PublicKey.Y)
	if code, _ := grant(signed(handle, 100)); code != http.StatusBadRequest {
		t.Fatalf("a binding by another passkey accepted: %d", code)
	}
	f.passkey = elliptic.Marshal(elliptic.P256(), holder.PublicKey.X, holder.PublicKey.Y)
	code, out := grant(signed(handle, 100))
	if code != http.StatusOK || out["ledger"] != handle {
		t.Fatalf("grant: %d %v", code, out)
	}
	c, err := f.store.GetBySubject("sub:user-1", f.appID)
	if err != nil || c.Ledger != handle || c.WalletSig == "" || c.UserID != "user-1" || c.HolderPub != pub {
		t.Fatalf("stored consent: %+v %v", c, err)
	}
	if _, err := f.store.GetBySubject("user-1", f.appID); err == nil {
		t.Fatal("the consent answered to the account, not the subject")
	}

	// The platform is told, once the outbox runs; a down control plane is
	// retried, not forgotten.
	fail = true
	if n := ob.DeliverPending(context.Background()); n != 0 || ob.Pending() != 1 {
		t.Fatalf("delivered through a down control plane: n=%d pending=%d", n, ob.Pending())
	}
	// Due again only after the backoff; force it.
	if _, err := f.store.db.Exec(`UPDATE ledger_outbox SET next_at = created_at`); err != nil {
		t.Fatal(err)
	}
	fail = false
	if n := ob.DeliverPending(context.Background()); n != 1 || ob.Pending() != 0 {
		t.Fatalf("delivery: n=%d pending=%d", n, ob.Pending())
	}
	mu.Lock()
	st := told[0]
	mu.Unlock()
	if st["kind"] != "register" || st["ledger"] != handle || st["account"] != "user-1" || st["app_id"] != f.appID || st["wallet_sig"] == "" || st["aud"] != "privasys-billing" {
		t.Fatalf("statement: %v", st)
	}

	// The spend token names the subject the app used and carries the handle.
	code, tok := f.token(t, "sub:user-1", f.assertion(t, nil))
	if code != http.StatusOK {
		t.Fatalf("token: %d %v", code, tok)
	}
	parsed, _, _ := jwt.NewParser().ParseUnverified(tok["spend_token"].(string), jwt.MapClaims{})
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["ledger"] != handle || claims["sub"] != "sub:user-1" {
		t.Fatalf("token claims: %v", claims)
	}
	if code, _ := f.token(t, "user-1", f.assertion(t, func(c jwt.MapClaims) { c["jti"] = "j2" })); code != http.StatusForbidden {
		t.Fatalf("a token for the account id, not the subject: %d", code)
	}

	// Withdrawing the consent tells the platform the handle is dead.
	r := httptest.NewRequest(http.MethodDelete, "/spend/consents/"+f.appID, nil)
	r.SetPathValue("app_id", f.appID)
	r.Header.Set("X-Test-User", "user-1")
	w := httptest.NewRecorder()
	f.h.HandleRevokeConsent(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if n := ob.DeliverPending(context.Background()); n != 1 {
		t.Fatalf("revoke delivered: %d", n)
	}
	mu.Lock()
	last := told[len(told)-1]
	mu.Unlock()
	if last["kind"] != "revoke" || last["ledger"] != handle {
		t.Fatalf("revoke statement: %v", last)
	}
}
