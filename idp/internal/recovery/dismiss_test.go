// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package recovery

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/push"
)

const testDismissKey = "AbCdEfGhIjKlMnOpQrStUv"

// captureDismiss records what would have been pushed.
func captureDismiss(t *testing.T) func(n int) []push.Message {
	t.Helper()
	var mu sync.Mutex
	var sent []push.Message
	got := make(chan struct{}, 16)
	sendDismiss = func(_ context.Context, _ push.Store, _ string, m push.Message) error {
		mu.Lock()
		sent = append(sent, m)
		mu.Unlock()
		got <- struct{}{}
		return nil
	}
	t.Cleanup(func() { sendDismiss = push.Notify })
	return func(n int) []push.Message {
		for i := 0; i < n; i++ {
			select {
			case <-got:
			case <-time.After(2 * time.Second):
				t.Fatalf("only %d of %d pushes sent", i, n)
			}
		}
		// Anything more would be a push too many.
		select {
		case <-got:
			t.Fatalf("more than %d pushes sent", n)
		case <-time.After(50 * time.Millisecond):
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]push.Message(nil), sent...)
	}
}

func dismissMux(t *testing.T) (*http.ServeMux, func(user, tag, token string)) {
	t.Helper()
	h, db, mux := identityTestHandler(t)
	mux.HandleFunc("POST /push/dismiss", h.HandleDismissNotification)
	return mux, func(user, tag, token string) {
		if err := db.UpsertDevicePushTarget(user, tag, token, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDismissReachesTheHoldersOtherPhonesOnly(t *testing.T) {
	mux, register := dismissMux(t)
	register("alice-drive", tagA, "tokA")
	register("alice-drive", tagB, "tokB")
	register("bob", tagB, "tokBob")
	wait := captureDismiss(t)

	rec := call(mux, "POST", "/push/dismiss", `{"push_token":"tokA","key":"`+testDismissKey+`"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("dismiss: %d %s", rec.Code, rec.Body)
	}
	sent := wait(1)
	m := sent[0]
	if m.Token != "tokB" || !m.Background || m.Data["type"] != "notification-dismiss" || m.Data["key"] != testDismissKey {
		t.Fatalf("sent %+v, want one silent dismiss to tokB", m)
	}
}

func TestDismissReachesEachPhoneOnceAcrossIdentities(t *testing.T) {
	mux, register := dismissMux(t)
	// One phone pair registered under two of the holder's identities.
	register("alice-drive", tagA, "tokA")
	register("alice-drive", tagB, "tokB")
	register("alice-ai", tagA, "tokA")
	register("alice-ai", tagB, "tokB")
	wait := captureDismiss(t)

	call(mux, "POST", "/push/dismiss", `{"push_token":"tokA","key":"`+testDismissKey+`"}`, "")
	var tokens []string
	for _, m := range wait(1) {
		tokens = append(tokens, m.Token)
	}
	sort.Strings(tokens)
	if len(tokens) != 1 || tokens[0] != "tokB" {
		t.Fatalf("tokens %v", tokens)
	}
}

func TestDismissFromAnUnknownTokenSendsNothingAndSaysTheSame(t *testing.T) {
	mux, register := dismissMux(t)
	register("alice-drive", tagA, "tokA")
	wait := captureDismiss(t)

	rec := call(mux, "POST", "/push/dismiss", `{"push_token":"nobody","key":"`+testDismissKey+`"}`, "")
	if rec.Code != http.StatusOK || rec.Body.String() != `{"status":"ok"}`+"\n" && rec.Body.String() != `{"status":"ok"}` {
		t.Fatalf("unknown token: %d %q", rec.Code, rec.Body)
	}
	wait(0)
}

func TestDismissRefusesABadRequest(t *testing.T) {
	mux, _ := dismissMux(t)
	for _, body := range []string{
		`{"push_token":"tokA","key":"short"}`,
		`{"push_token":"tokA","key":"has spaces in it, sixteen+"}`,
		`{"key":"` + testDismissKey + `"}`,
	} {
		if rec := call(mux, "POST", "/push/dismiss", body, ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", body, rec.Code)
		}
	}
}
