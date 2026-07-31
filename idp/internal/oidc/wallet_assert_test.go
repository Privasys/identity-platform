// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"testing"
	"time"
)

// The wallet's assert and the session's completion can arrive in either
// order; both must leave the auth code wallet-class.

func TestMarkWalletAssertedBeforeCompletion(t *testing.T) {
	ss := NewSessionStore()
	cs := NewCodeStore()
	ss.Create(&AuthSession{SessionID: "s1", ExpiresAt: time.Now().Add(time.Minute)})

	code, ok := ss.MarkWalletAsserted("s1", "inst-1")
	if !ok || code != "" {
		t.Fatalf("expected pending-session mark, got code=%q ok=%v", code, ok)
	}

	// Completion mints the code from the session flag (as the fido2 and
	// session/complete paths do).
	s, _ := ss.Get("s1")
	if !s.WalletAsserted {
		t.Fatal("session not marked")
	}
	authCode := cs.Create(&AuthCode{UserID: "u1", WalletVerified: s.WalletAsserted})
	ss.Complete("s1", "u1", authCode)

	ac, ok := cs.Consume(authCode)
	if !ok || !ac.WalletVerified {
		t.Fatalf("code must carry the wallet class: %+v", ac)
	}
}

func TestMarkWalletAssertedAfterCompletion(t *testing.T) {
	ss := NewSessionStore()
	cs := NewCodeStore()
	ss.Create(&AuthSession{SessionID: "s2", ExpiresAt: time.Now().Add(time.Minute)})

	// Completion first (assert loses the race): the code is minted without
	// the class.
	authCode := cs.Create(&AuthCode{UserID: "u1"})
	ss.Complete("s2", "u1", authCode)

	code, ok := ss.MarkWalletAsserted("s2", "inst-1")
	if !ok || code != authCode {
		t.Fatalf("expected the completed code back, got %q ok=%v", code, ok)
	}
	cs.MarkWalletVerified(code)

	ac, ok := cs.Consume(authCode)
	if !ok || !ac.WalletVerified {
		t.Fatalf("patched code must carry the wallet class: %+v", ac)
	}
}

func TestMarkWalletAssertedUnknownSession(t *testing.T) {
	ss := NewSessionStore()
	if _, ok := ss.MarkWalletAsserted("nope", "inst-1"); ok {
		t.Fatal("unknown session must not be assertable")
	}
}

func TestMarkWalletVerifiedConsumedCodeIsNoop(t *testing.T) {
	cs := NewCodeStore()
	code := cs.Create(&AuthCode{UserID: "u1"})
	if _, ok := cs.Consume(code); !ok {
		t.Fatal("consume failed")
	}
	// Patching after consumption changes nothing and must not panic; the
	// token was issued without the class (exemption lost, never granted).
	cs.MarkWalletVerified(code)
}
