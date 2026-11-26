// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package recovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/store"
)

type bindRig struct {
	t   *testing.T
	h   *Handler
	db  *store.DB
	now time.Time
}

func newBindRig(t *testing.T) *bindRig {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, u := range []string{"alice", "alice-2", "bob", "bob-2", "mallory"} {
		if err := db.EnsureUser(u); err != nil {
			t.Fatal(err)
		}
	}
	r := &bindRig{t: t, db: db, now: time.Unix(1_800_000_000, 0)}
	r.h = &Handler{db: db, walletSession: func(tok string) (string, bool) { return tok, tok != "" }}
	old := pushBinds
	pushBinds = &pushBindState{
		challenges: map[string]pushBindChallenge{},
		now:        func() time.Time { return r.now },
	}
	t.Cleanup(func() { pushBinds = old })
	return r
}

type bindKey struct {
	pub  string
	priv ed25519.PrivateKey
}

func newBindKey(t *testing.T) bindKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return bindKey{pub: base64.RawURLEncoding.EncodeToString(pub), priv: priv}
}

func (k bindKey) sign(msg []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, msg))
}

// register posts a registration as user and reports whether it came back bound.
func (r *bindRig) register(user, token string, body map[string]any) bool {
	r.t.Helper()
	body["push_token"] = token
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/push-token", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer wallet:"+user)
	w := httptest.NewRecorder()
	r.h.HandleRegisterPushToken(w, req)
	if w.Code != http.StatusOK {
		r.t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	var out struct {
		Bound bool `json:"bound"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return out.Bound
}

func (r *bindRig) signed(user, token string, k bindKey) bool {
	at := r.now.Unix()
	return r.register(user, token, map[string]any{
		"bind_pub": k.pub, "issued_at": at, "bind_sig": k.sign(pushRegisterText(token, user, at)),
	})
}

func (r *bindRig) answer(token, bindPub, nonce, sig string) int {
	raw, _ := json.Marshal(map[string]string{"push_token": token, "bind_pub": bindPub, "nonce": nonce, "sig": sig})
	w := httptest.NewRecorder()
	r.h.HandleBindPushToken(w, httptest.NewRequest(http.MethodPost, "/push-token/bind", bytes.NewReader(raw)))
	return w.Code
}

// bind takes a device through the whole exchange for one identity: it
// registers, a push the holder sees carries the challenge, the wallet answers,
// and it registers again, signed.
func (r *bindRig) bind(user, token string, k bindKey) {
	r.t.Helper()
	if r.register(user, token, map[string]any{"bind_pub": k.pub}) {
		r.t.Fatal("bound before any challenge was answered")
	}
	nonce, pub := r.h.BindChallengeFor(user, token)
	if nonce == "" || pub != k.pub {
		r.t.Fatalf("no challenge to carry: nonce %q, key %q", nonce, pub)
	}
	if code := r.answer(token, k.pub, nonce, k.sign(pushBindText(token, nonce))); code != http.StatusOK {
		r.t.Fatalf("answer: %d", code)
	}
	if !r.signed(user, token, k) {
		r.t.Fatal("a signed registration under the proven key was not bound")
	}
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestPushBindWholeExchange(t *testing.T) {
	r := newBindRig(t)
	k := newBindKey(t)
	r.bind("alice", "tok-phone", k)
	if !has(r.db.BadgeTokens("alice"), "tok-phone") || !has(r.db.PushTokenUsers("tok-phone"), "alice") {
		t.Fatal("the bound device is not counted")
	}
	// Proven and bound: no push carries a challenge any more.
	if nonce, _ := r.h.BindChallengeFor("alice", "tok-phone"); nonce != "" {
		t.Fatal("a challenge is carried for a registration already bound")
	}
	// A second identity on the same phone is bound by its signature alone.
	if !r.signed("alice-2", "tok-phone", k) {
		t.Fatal("second identity not bound by its signature")
	}
}

// What a push carries, and when.
func TestPushBindChallengeIsCarriedOnlyWhenNeeded(t *testing.T) {
	r := newBindRig(t)
	k := newBindKey(t)

	// Nothing registered, and a wallet that named no key: nothing to carry.
	if nonce, _ := r.h.BindChallengeFor("alice", "tok"); nonce != "" {
		t.Fatal("a challenge for a token nobody registered")
	}
	r.register("alice", "tok", map[string]any{})
	if nonce, _ := r.h.BindChallengeFor("alice", "tok"); nonce != "" {
		t.Fatal("a challenge for a registration that named no key")
	}
	if nonce, _ := r.h.BindChallengeFor("", "tok"); nonce != "" {
		t.Fatal("a challenge for no identity")
	}

	// A key named, not proven: every push carries the SAME nonce while it lives.
	r.register("alice", "tok", map[string]any{"bind_pub": k.pub})
	first, pub := r.h.BindChallengeFor("alice", "tok")
	if first == "" || pub != k.pub {
		t.Fatalf("nothing to carry: %q %q", first, pub)
	}
	r.now = r.now.Add(5 * time.Minute)
	if again, _ := r.h.BindChallengeFor("alice", "tok"); again != first {
		t.Fatal("a second push carried a different nonce while the first was open")
	}
	// Another identity's push to the same token carries nothing of Alice's.
	if nonce, _ := r.h.BindChallengeFor("bob", "tok"); nonce != "" {
		t.Fatal("a challenge carried in a push for an identity that did not register the token")
	}

	// Lapsed: the next push carries a new one, and the old one is refused.
	r.now = r.now.Add(pushBindTTL)
	fresh, _ := r.h.BindChallengeFor("alice", "tok")
	if fresh == "" || fresh == first {
		t.Fatalf("after expiry: %q (was %q)", fresh, first)
	}
	if code := r.answer("tok", k.pub, first, k.sign(pushBindText("tok", first))); code != http.StatusForbidden {
		t.Fatalf("an expired nonce: %d", code)
	}
	// That wrong answer spent the open challenge; the next push opens another.
	fresh, _ = r.h.BindChallengeFor("alice", "tok")
	if code := r.answer("tok", k.pub, fresh, k.sign(pushBindText("tok", fresh))); code != http.StatusOK {
		t.Fatalf("a fresh nonce: %d", code)
	}
	// Used once.
	if code := r.answer("tok", k.pub, fresh, k.sign(pushBindText("tok", fresh))); code != http.StatusForbidden {
		t.Fatalf("a second use: %d", code)
	}
	// The key is proven: what the registration lacks now is its signature,
	// which no push can supply, so nothing is carried.
	if nonce, _ := r.h.BindChallengeFor("alice", "tok"); nonce != "" {
		t.Fatal("a challenge carried for a key already proven")
	}
}

func TestPushBindOldWalletStaysUnbound(t *testing.T) {
	r := newBindRig(t)
	if r.register("alice", "tok-phone", map[string]any{}) {
		t.Fatal("a registration without a key came back bound")
	}
	if len(r.db.BadgeTokens("alice")) != 0 || len(r.db.PushTokenUsers("tok-phone")) != 0 {
		t.Fatal("an unbound token is counted")
	}
	// Its own pushes still reach it.
	if !has(r.db.GetPushTokens("alice"), "tok-phone") {
		t.Fatal("the identity lost its own push target")
	}
}

// Mallory knows Alice's push token and her device's public binding key.
func TestPushBindClaimingAnotherDevice(t *testing.T) {
	r := newBindRig(t)
	alice := newBindKey(t)
	r.bind("alice", "tok-alice", alice)

	// Naming Alice's key, without her signature: unbound, and nothing to carry.
	if r.register("mallory", "tok-alice", map[string]any{"bind_pub": alice.pub}) {
		t.Fatal("bound by naming another device's key")
	}
	if nonce, _ := r.h.BindChallengeFor("mallory", "tok-alice"); nonce != "" {
		t.Fatal("naming a proven key opened a challenge")
	}
	// A signature Alice made for her own subject does not serve Mallory.
	at := r.now.Unix()
	if r.register("mallory", "tok-alice", map[string]any{
		"bind_pub": alice.pub, "issued_at": at, "bind_sig": alice.sign(pushRegisterText("tok-alice", "alice", at)),
	}) {
		t.Fatal("bound with a signature over another subject")
	}
	// Her own key: the challenge rides only in pushes for Mallory's identity
	// to Alice's device, which Mallory never sees and Alice's wallet ignores,
	// since the key named is not its own. A made-up nonce, properly signed, is
	// refused and spends the challenge.
	mal := newBindKey(t)
	if r.register("mallory", "tok-alice", map[string]any{"bind_pub": mal.pub}) {
		t.Fatal("bound with an unproven key")
	}
	nonce, pub := r.h.BindChallengeFor("mallory", "tok-alice")
	if nonce == "" || pub != mal.pub {
		t.Fatal("no challenge for a new key")
	}
	if n, _ := r.h.BindChallengeFor("alice", "tok-alice"); n != "" {
		t.Fatal("Alice's own pushes carry Mallory's challenge")
	}
	if code := r.answer("tok-alice", mal.pub, "guess", mal.sign(pushBindText("tok-alice", "guess"))); code != http.StatusForbidden {
		t.Fatalf("a guessed nonce: %d", code)
	}
	if code := r.answer("tok-alice", mal.pub, nonce, mal.sign(pushBindText("tok-alice", nonce))); code != http.StatusForbidden {
		t.Fatalf("the challenge survived a wrong answer: %d", code)
	}
	if has(r.db.PushTokenUsers("tok-alice"), "mallory") || !has(r.db.PushTokenUsers("tok-alice"), "alice") {
		t.Fatalf("users of the token: %v", r.db.PushTokenUsers("tok-alice"))
	}
	if len(r.db.BadgeTokens("mallory")) != 0 {
		t.Fatal("the claimed token takes Mallory's count")
	}
}

func TestPushBindAnswerChecks(t *testing.T) {
	r := newBindRig(t)
	k, other := newBindKey(t), newBindKey(t)
	r.register("alice", "tok", map[string]any{"bind_pub": k.pub})
	nonce, _ := r.h.BindChallengeFor("alice", "tok")
	// Signed by a key the challenge was not opened for.
	if code := r.answer("tok", k.pub, nonce, other.sign(pushBindText("tok", nonce))); code != http.StatusForbidden {
		t.Fatalf("wrong signer: %d", code)
	}
	if r.db.PushTokenBindKey("tok") != "" {
		t.Fatal("a refused answer recorded a key")
	}
	// A stale signed registration is not taken.
	r.bind("bob", "tok-bob", k)
	at := r.now.Add(-pushRegisterWindow - time.Second).Unix()
	if r.register("bob-2", "tok-bob", map[string]any{
		"bind_pub": k.pub, "issued_at": at, "bind_sig": k.sign(pushRegisterText("tok-bob", "bob-2", at)),
	}) {
		t.Fatal("bound with a signature from outside the window")
	}
}

// A new key for a bound token is taken only after its own challenge, and the
// registrations under the old key stop counting.
func TestPushBindRebind(t *testing.T) {
	r := newBindRig(t)
	old, fresh := newBindKey(t), newBindKey(t)
	r.bind("alice", "tok", old)
	r.bind("alice", "tok", fresh)
	if r.db.PushTokenBindKey("tok") != fresh.pub {
		t.Fatal("the new key was not recorded")
	}
	if r.signed("alice-2", "tok", old) {
		t.Fatal("the replaced key still binds")
	}
}

// Another phone of the holder is a peer only when both are bound.
func TestPushPeersAreBoundOnly(t *testing.T) {
	r := newBindRig(t)
	for _, d := range [][2]string{{"tag-phone-000000000000", "tok-phone"}, {"tag-pad-00000000000000", "tok-pad"}} {
		if err := r.db.UpsertDevicePushTarget("alice", d[0], d[1], ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.db.SetPushBinding("alice", "tok-phone", "key-phone", true); err != nil {
		t.Fatal(err)
	}
	if peers := r.db.GetPushPeers("tok-phone"); len(peers) != 0 {
		t.Fatalf("an unbound token is a peer: %v", peers)
	}
	if peers := r.db.GetPushPeers("tok-pad"); len(peers) != 0 {
		t.Fatalf("an unbound token has peers: %v", peers)
	}
	if err := r.db.SetPushBinding("alice", "tok-pad", "key-pad", true); err != nil {
		t.Fatal(err)
	}
	if peers := r.db.GetPushPeers("tok-phone"); len(peers) != 1 || peers[0].Token != "tok-pad" {
		t.Fatalf("peers of the phone: %v", peers)
	}
}
