// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/push"
	"github.com/Privasys/idp/internal/store"
)

type bindRig struct {
	t    *testing.T
	h    *Handler
	db   *store.DB
	now  time.Time
	sent chan push.Message
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
	r := &bindRig{t: t, db: db, now: time.Unix(1_800_000_000, 0), sent: make(chan push.Message, 16)}
	r.h = &Handler{db: db, walletSession: func(tok string) (string, bool) { return tok, tok != "" }}
	old := pushBinds
	pushBinds = &pushBindState{
		challenges: map[string]pushBindChallenge{},
		sent:       map[string][]time.Time{},
		now:        func() time.Time { return r.now },
		send: func(_ context.Context, _ push.Store, _ string, m push.Message) error {
			r.sent <- m
			return nil
		},
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

// challenge waits for the challenge push, or reports that none was sent.
func (r *bindRig) challenge() (push.Message, bool) {
	select {
	case m := <-r.sent:
		return m, true
	case <-time.After(200 * time.Millisecond):
		return push.Message{}, false
	}
}

func (r *bindRig) answer(token, bindPub, nonce, sig string) int {
	raw, _ := json.Marshal(map[string]string{"push_token": token, "bind_pub": bindPub, "nonce": nonce, "sig": sig})
	w := httptest.NewRecorder()
	r.h.HandleBindPushToken(w, httptest.NewRequest(http.MethodPost, "/push-token/bind", bytes.NewReader(raw)))
	return w.Code
}

// bind takes a device through the whole exchange for one identity.
func (r *bindRig) bind(user, token string, k bindKey) {
	r.t.Helper()
	if r.register(user, token, map[string]any{"bind_pub": k.pub}) {
		r.t.Fatal("bound before any challenge was answered")
	}
	m, ok := r.challenge()
	if !ok {
		r.t.Fatal("no challenge was sent")
	}
	if m.Token != token || !m.Background || m.Data["type"] != "push-bind" || m.Data["bind_pub"] != k.pub {
		r.t.Fatalf("challenge push: %+v", m)
	}
	if code := r.answer(token, k.pub, m.Data["nonce"], k.sign(pushBindText(token, m.Data["nonce"]))); code != http.StatusOK {
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
	// A second identity on the same phone needs no new challenge.
	if !r.signed("alice-2", "tok-phone", k) {
		t.Fatal("second identity not bound by its signature")
	}
	if _, sent := r.challenge(); sent {
		t.Fatal("a challenge was sent for a key already proven")
	}
}

func TestPushBindOldWalletStaysUnbound(t *testing.T) {
	r := newBindRig(t)
	if r.register("alice", "tok-phone", map[string]any{}) {
		t.Fatal("a registration without a key came back bound")
	}
	if _, sent := r.challenge(); sent {
		t.Fatal("a challenge was sent to a wallet that offered no key")
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

	// Naming Alice's key, without her signature: unbound, and no push to her.
	if r.register("mallory", "tok-alice", map[string]any{"bind_pub": alice.pub}) {
		t.Fatal("bound by naming another device's key")
	}
	if _, sent := r.challenge(); sent {
		t.Fatal("naming a proven key sent its device a push")
	}
	// A signature Alice made for her own subject does not serve Mallory.
	at := r.now.Unix()
	if r.register("mallory", "tok-alice", map[string]any{
		"bind_pub": alice.pub, "issued_at": at, "bind_sig": alice.sign(pushRegisterText("tok-alice", "alice", at)),
	}) {
		t.Fatal("bound with a signature over another subject")
	}
	// Her own key: Alice's device is challenged, and Mallory never sees the
	// nonce. A made-up one, properly signed, is refused and spends the challenge.
	mal := newBindKey(t)
	r.now = r.now.Add(2 * time.Minute)
	if r.register("mallory", "tok-alice", map[string]any{"bind_pub": mal.pub}) {
		t.Fatal("bound with an unproven key")
	}
	m, sent := r.challenge()
	if !sent {
		t.Fatal("no challenge for a new key")
	}
	if code := r.answer("tok-alice", mal.pub, "guess", mal.sign(pushBindText("tok-alice", "guess"))); code != http.StatusForbidden {
		t.Fatalf("a guessed nonce: %d", code)
	}
	if code := r.answer("tok-alice", mal.pub, m.Data["nonce"], mal.sign(pushBindText("tok-alice", m.Data["nonce"]))); code != http.StatusForbidden {
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
	m, _ := r.challenge()
	nonce := m.Data["nonce"]
	// Signed by a key the challenge was not opened for.
	if code := r.answer("tok", k.pub, nonce, other.sign(pushBindText("tok", nonce))); code != http.StatusForbidden {
		t.Fatalf("wrong signer: %d", code)
	}
	// Expired.
	r.now = r.now.Add(2 * time.Minute)
	r.register("alice", "tok", map[string]any{"bind_pub": k.pub})
	m, _ = r.challenge()
	r.now = r.now.Add(pushBindTTL + time.Second)
	if code := r.answer("tok", k.pub, m.Data["nonce"], k.sign(pushBindText("tok", m.Data["nonce"]))); code != http.StatusForbidden {
		t.Fatalf("expired: %d", code)
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

func TestPushBindRateLimit(t *testing.T) {
	r := newBindRig(t)
	k := newBindKey(t)
	r.register("alice", "tok", map[string]any{"bind_pub": k.pub})
	if _, sent := r.challenge(); !sent {
		t.Fatal("first challenge not sent")
	}
	r.register("alice", "tok", map[string]any{"bind_pub": k.pub})
	if _, sent := r.challenge(); sent {
		t.Fatal("a second challenge within the minute")
	}
	sentToday := 1
	for i := 0; i < 30; i++ {
		r.now = r.now.Add(61 * time.Second)
		r.register("alice", "tok", map[string]any{"bind_pub": k.pub})
		if _, sent := r.challenge(); sent {
			sentToday++
		}
	}
	if sentToday != pushBindPerDay {
		t.Fatalf("challenges in a day: %d", sentToday)
	}
}

// A new key for a bound token is taken only after its own challenge, and the
// registrations under the old key stop counting.
func TestPushBindRebind(t *testing.T) {
	r := newBindRig(t)
	old, fresh := newBindKey(t), newBindKey(t)
	r.bind("alice", "tok", old)
	r.now = r.now.Add(2 * time.Minute)
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
