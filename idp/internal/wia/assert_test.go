// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package wia

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

// issueTestWIA mints a wia+jwt for the given holder key with the handler's
// own issuer, mirroring what enrolment produces.
func issueTestWIA(t *testing.T, iss *tokens.Issuer, k *ecdsa.PrivateKey) string {
	t.Helper()
	wiaJWT, err := iss.IssueWIA(tokens.WIAClaims{
		HolderJWK: tokens.ECPublicJWK(&k.PublicKey),
		Level:     "tee",
		Platform:  "android",
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("issue WIA: %v", err)
	}
	return wiaJWT
}

func assertSig(t *testing.T, k *ecdsa.PrivateKey, sessionID string, ts int64, nonce string) string {
	t.Helper()
	digest := sha256.Sum256(AssertPayload(sessionID, ts, nonce))
	der, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// recordingAsserter captures the callback invocation and returns a fixed
// outcome.
type recordingAsserter struct {
	sessionID   string
	instanceKey string
	calls       int
	outcome     AssertOutcome
}

func (a *recordingAsserter) fn(sessionID, instanceKey string) AssertOutcome {
	a.calls++
	a.sessionID = sessionID
	a.instanceKey = instanceKey
	return a.outcome
}

func postAssert(h *Handler, a *recordingAsserter, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/session/assert-wallet", strings.NewReader(string(b)))
	w := httptest.NewRecorder()
	h.HandleAssertSession(a.fn)(w, r)
	return w
}

func TestAssertSessionHappyPath(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := time.Now().Unix()

	a := &recordingAsserter{outcome: AssertMarked}
	w := postAssert(h, a, map[string]interface{}{
		"session_id": "sess-1",
		"ts":         ts,
		"nonce":      "n-1",
		"wia":        issueTestWIA(t, iss, holder),
		"holder_sig": assertSig(t, holder, "sess-1", ts, "n-1"),
	})
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if a.calls != 1 || a.sessionID != "sess-1" || a.instanceKey == "" {
		t.Fatalf("asserter not invoked correctly: %+v", a)
	}
}

func TestAssertSessionPatchesCompleted(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := time.Now().Unix()

	a := &recordingAsserter{outcome: AssertPatchedCompletedCode}
	w := postAssert(h, a, map[string]interface{}{
		"session_id": "sess-done",
		"ts":         ts,
		"nonce":      "n-2",
		"wia":        issueTestWIA(t, iss, holder),
		"holder_sig": assertSig(t, holder, "sess-done", ts, "n-2"),
	})
	if w.Code != 200 {
		t.Fatalf("expected 200 for a completed-session patch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAssertSessionUnknownSession(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := time.Now().Unix()

	a := &recordingAsserter{outcome: AssertSessionNotFound}
	w := postAssert(h, a, map[string]interface{}{
		"session_id": "nope",
		"ts":         ts,
		"nonce":      "n-3",
		"wia":        issueTestWIA(t, iss, holder),
		"holder_sig": assertSig(t, holder, "nope", ts, "n-3"),
	})
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAssertSessionRejectsWrongHolderKey(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := time.Now().Unix()

	a := &recordingAsserter{outcome: AssertMarked}
	// WIA binds holder; the PoP is signed by a DIFFERENT key.
	w := postAssert(h, a, map[string]interface{}{
		"session_id": "sess-1",
		"ts":         ts,
		"nonce":      "n-4",
		"wia":        issueTestWIA(t, iss, holder),
		"holder_sig": assertSig(t, other, "sess-1", ts, "n-4"),
	})
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if a.calls != 0 {
		t.Fatal("asserter must not run on a failed PoP")
	}
}

func TestAssertSessionRejectsTamperedFields(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := time.Now().Unix()
	wiaJWT := issueTestWIA(t, iss, holder)
	sig := assertSig(t, holder, "sess-1", ts, "n-5")

	// The signature binds the session id: replaying it for another session
	// must fail.
	a := &recordingAsserter{outcome: AssertMarked}
	w := postAssert(h, a, map[string]interface{}{
		"session_id": "sess-2",
		"ts":         ts,
		"nonce":      "n-5",
		"wia":        wiaJWT,
		"holder_sig": sig,
	})
	if w.Code != 403 {
		t.Fatalf("expected 403 for a session swap, got %d", w.Code)
	}
	// And the nonce.
	w = postAssert(h, a, map[string]interface{}{
		"session_id": "sess-1",
		"ts":         ts,
		"nonce":      "n-other",
		"wia":        wiaJWT,
		"holder_sig": sig,
	})
	if w.Code != 403 {
		t.Fatalf("expected 403 for a nonce swap, got %d", w.Code)
	}
	if a.calls != 0 {
		t.Fatal("asserter must not run on tampered fields")
	}
}

func TestAssertSessionRejectsStaleTimestamp(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := time.Now().Add(-10 * time.Minute).Unix()

	a := &recordingAsserter{outcome: AssertMarked}
	w := postAssert(h, a, map[string]interface{}{
		"session_id": "sess-1",
		"ts":         ts,
		"nonce":      "n-6",
		"wia":        issueTestWIA(t, iss, holder),
		"holder_sig": assertSig(t, holder, "sess-1", ts, "n-6"),
	})
	if w.Code != 400 {
		t.Fatalf("expected 400 for a stale ts, got %d", w.Code)
	}
}

func TestAssertSessionRejectsNonWIAToken(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := time.Now().Unix()

	// Signed by the same key but typ=voucher+jwt: must be refused before
	// any claim is read.
	voucher, err := iss.IssueVoucher(tokens.VoucherClaims{JTI: "j", RPID: "rp", Provider: "p", TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue voucher: %v", err)
	}
	a := &recordingAsserter{outcome: AssertMarked}
	w := postAssert(h, a, map[string]interface{}{
		"session_id": "sess-1",
		"ts":         ts,
		"nonce":      "n-7",
		"wia":        voucher,
		"holder_sig": assertSig(t, holder, "sess-1", ts, "n-7"),
	})
	if w.Code != 403 {
		t.Fatalf("expected 403 for a non-wia token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAssertSessionRejectsForeignSigner(t *testing.T) {
	h, _ := newTestHandler(t, "soft")
	// A WIA signed by a DIFFERENT issuer key (attacker-minted).
	foreign, foreignIss := newTestHandler(t, "soft")
	_ = foreign
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := time.Now().Unix()

	a := &recordingAsserter{outcome: AssertMarked}
	w := postAssert(h, a, map[string]interface{}{
		"session_id": "sess-1",
		"ts":         ts,
		"nonce":      "n-8",
		"wia":        issueTestWIA(t, foreignIss, holder),
		"holder_sig": assertSig(t, holder, "sess-1", ts, "n-8"),
	})
	if w.Code != 403 {
		t.Fatalf("expected 403 for a foreign-signed WIA, got %d: %s", w.Code, w.Body.String())
	}
}
