// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/store"
)

func identityTestHandler(t *testing.T) (*Handler, *store.DB, *http.ServeMux) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, u := range []string{"alice-drive", "alice-ai", "bob"} {
		if _, err := db.Exec("INSERT INTO users (user_id) VALUES (?)", u); err != nil {
			t.Fatalf("insert user: %v", err)
		}
	}
	h := NewHandler(db, nil, nil)
	// The bearer "wallet:<user>" stands for that identity's wallet session.
	h.SetWalletSessionResolver(func(token string) (string, bool) { return token, token != "" })
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /recovery/identity-key", h.HandleSetIdentityKey)
	mux.HandleFunc("POST /recovery/identity/begin", h.HandleBeginIdentityRecovery)
	mux.HandleFunc("POST /recovery/identity/complete", h.HandleCompleteIdentityRecovery)
	return h, db, mux
}

func call(mux *http.ServeMux, method, path, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:4000"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func keyFor(seed byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	return ed25519.NewKeyFromSeed(s)
}

func setKey(t *testing.T, mux *http.ServeMux, user string, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	return call(mux, "PUT", "/recovery/identity-key", `{"public_key":"`+b64(pub)+`"}`, "wallet:"+user)
}

func begin(t *testing.T, mux *http.ServeMux, user string) (int, []byte) {
	t.Helper()
	rec := call(mux, "POST", "/recovery/identity/begin", `{"user_id":"`+user+`"}`, "")
	var out struct {
		Challenge string `json:"challenge"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	c, _ := base64.RawURLEncoding.DecodeString(out.Challenge)
	return rec.Code, c
}

func complete(mux *http.ServeMux, user string, challenge, sig []byte) *httptest.ResponseRecorder {
	return call(mux, "POST", "/recovery/identity/complete",
		`{"user_id":"`+user+`","challenge":"`+b64(challenge)+`","signature":"`+b64(sig)+`"}`, "")
}

func TestAnIdentityIsRecoveredByItsOwnKey(t *testing.T) {
	_, db, mux := identityTestHandler(t)
	priv := keyFor(1)
	if rec := setKey(t, mux, "alice-drive", priv); rec.Code != http.StatusOK {
		t.Fatalf("set key: %d %s", rec.Code, rec.Body.String())
	}
	// The old phone's passkey, which a recovery must revoke.
	if _, err := db.Exec(
		"INSERT INTO credentials (credential_id, user_id, public_key) VALUES ('old', 'alice-drive', x'00')",
	); err != nil {
		t.Fatal(err)
	}

	code, challenge := begin(t, mux, "alice-drive")
	if code != http.StatusOK || len(challenge) != 32 {
		t.Fatalf("begin: %d, challenge %d bytes", code, len(challenge))
	}
	sig := ed25519.Sign(priv, IdentityRecoveryMessage("alice-drive", challenge))
	if rec := complete(mux, "alice-drive", challenge, sig); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}

	// The takeover gate in fido2/register/begin looks for exactly this row.
	var recovered int
	_ = db.QueryRow(`SELECT COUNT(*) FROM recovery_requests
		WHERE user_id = 'alice-drive' AND status = 'completed' AND expires_at > ?`, time.Now()).Scan(&recovered)
	if recovered != 1 {
		t.Fatalf("completed recoveries for the identity: %d, want 1", recovered)
	}
	if n, _ := db.CountCredentials("alice-drive"); n != 0 {
		t.Fatalf("old passkeys left on the recovered identity: %d", n)
	}
	// Nothing happened to any other identity.
	_ = db.QueryRow(`SELECT COUNT(*) FROM recovery_requests WHERE user_id != 'alice-drive'`).Scan(&recovered)
	if recovered != 0 {
		t.Fatal("a recovery touched another identity")
	}
}

func TestRecoveryRefusals(t *testing.T) {
	_, _, mux := identityTestHandler(t)
	alice, bob := keyFor(1), keyFor(2)
	setKey(t, mux, "alice-drive", alice)
	setKey(t, mux, "bob", bob)

	// An identity with no key cannot be recovered this way.
	if code, _ := begin(t, mux, "alice-ai"); code != http.StatusNotFound {
		t.Fatalf("keyless identity begin: %d, want 404", code)
	}

	// Another identity's key does not recover this one.
	_, c := begin(t, mux, "alice-drive")
	if rec := complete(mux, "alice-drive", c, ed25519.Sign(bob, IdentityRecoveryMessage("alice-drive", c))); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong key: %d, want 403", rec.Code)
	}
	// A challenge is single use, even after a failure.
	if rec := complete(mux, "alice-drive", c, ed25519.Sign(alice, IdentityRecoveryMessage("alice-drive", c))); rec.Code != http.StatusBadRequest {
		t.Fatalf("reused challenge: %d, want 400", rec.Code)
	}

	// A challenge issued for one identity cannot complete another.
	_, c = begin(t, mux, "alice-drive")
	if rec := complete(mux, "bob", c, ed25519.Sign(bob, IdentityRecoveryMessage("bob", c))); rec.Code != http.StatusBadRequest {
		t.Fatalf("challenge moved to another identity: %d, want 400", rec.Code)
	}

	// A signature over another identity's message does not count.
	_, c = begin(t, mux, "alice-drive")
	if rec := complete(mux, "alice-drive", c, ed25519.Sign(alice, IdentityRecoveryMessage("bob", c))); rec.Code != http.StatusForbidden {
		t.Fatalf("signature for another id: %d, want 403", rec.Code)
	}
}

func TestARecoveryKeyIsSetOnce(t *testing.T) {
	_, _, mux := identityTestHandler(t)
	if rec := setKey(t, mux, "alice-drive", keyFor(1)); rec.Code != http.StatusOK {
		t.Fatalf("first set: %d", rec.Code)
	}
	if rec := setKey(t, mux, "alice-drive", keyFor(1)); rec.Code != http.StatusOK {
		t.Fatalf("same key again: %d, want 200", rec.Code)
	}
	if rec := setKey(t, mux, "alice-drive", keyFor(9)); rec.Code != http.StatusConflict {
		t.Fatalf("different key: %d, want 409", rec.Code)
	}
	if rec := call(mux, "PUT", "/recovery/identity-key", `{"public_key":"`+b64(keyFor(1).Public().(ed25519.PublicKey))+`"}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d, want 401", rec.Code)
	}
	if rec := call(mux, "PUT", "/recovery/identity-key", `{"public_key":"AAAA"}`, "wallet:bob"); rec.Code != http.StatusBadRequest {
		t.Fatalf("short key: %d, want 400", rec.Code)
	}
}

func TestIdentityRecoveryIsRateLimited(t *testing.T) {
	_, _, mux := identityTestHandler(t)
	setKey(t, mux, "alice-drive", keyFor(1))
	for i := 0; i < identityAttemptsPerIdentity; i++ {
		if code, _ := begin(t, mux, "alice-drive"); code != http.StatusOK {
			t.Fatalf("attempt %d: %d", i+1, code)
		}
	}
	if code, _ := begin(t, mux, "alice-drive"); code != http.StatusTooManyRequests {
		t.Fatalf("attempt past the limit: %d, want 429", code)
	}
}

func TestTheIdentityIndexRoundTrips(t *testing.T) {
	h, _, mux := identityTestHandler(t)
	mux.HandleFunc("PUT /recovery/identity-index", h.HandlePutIdentityIndex)
	mux.HandleFunc("GET /recovery/identity-index", h.HandleGetIdentityIndex)
	if rec := call(mux, "GET", "/recovery/identity-index", "", "wallet:alice-drive"); rec.Code != http.StatusNotFound {
		t.Fatalf("empty: %d", rec.Code)
	}
	if rec := call(mux, "PUT", "/recovery/identity-index", `{"blob":"AQID_-x"}`, "wallet:alice-drive"); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(mux, "GET", "/recovery/identity-index", "", "wallet:alice-drive"); !strings.Contains(rec.Body.String(), `"AQID_-x"`) {
		t.Fatalf("get: %s", rec.Body.String())
	}
	// Another account sees nothing of it.
	if rec := call(mux, "GET", "/recovery/identity-index", "", "wallet:bob"); rec.Code != http.StatusNotFound {
		t.Fatalf("other account: %d", rec.Code)
	}
	if rec := call(mux, "PUT", "/recovery/identity-index", `{"blob":"not base64!"}`, "wallet:alice-drive"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad blob: %d", rec.Code)
	}
}

// TestTheWalletVectorVerifies pins the contract with the wallet: the vector is
// produced by wallet/src/__tests__/identities.test.ts (its snapshot). A wallet
// that signs different bytes than this package verifies would fail here first.
func TestTheWalletVectorVerifies(t *testing.T) {
	const (
		userID = "XUz5Z1gsKjhFFhCeSjYvrgwfcxU-qFjnGLS_BByzxMA"
		pubB64 = "z3DyB32X65KsSnPkidEPLc-laAdCLnS0-XJiH815ORs"
		sigB64 = "awyQ8ZyD2TXrnKhWrTvr6Z6NBESAiMZ59_xm4lKXur0s6M88PAmHXfI12o0JD0pUCkOIqOp7amwB9kxgh7abAA"
	)
	pub, _ := base64.RawURLEncoding.DecodeString(pubB64)
	sig, _ := base64.RawURLEncoding.DecodeString(sigB64)
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), IdentityRecoveryMessage(userID, challenge), sig) {
		t.Fatal("the wallet's signature does not verify over the IdP's message")
	}
}
