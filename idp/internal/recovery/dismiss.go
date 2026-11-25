// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package recovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Privasys/idp/internal/push"
	"github.com/Privasys/idp/internal/store"
)

// dismissKey is what a wallet sends: a hash it derived from the notification
// (its type and request id), never the request id itself, so nothing about the
// request passes through here or through the push services a second time.
var dismissKey = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

const (
	// dismissPerToken bounds how many dismissals one phone can fan out in a day.
	dismissPerToken = 500
	dismissPerIP    = 2000
)

// sendDismiss sends one push; tests replace it.
var sendDismiss = push.Notify

// HandleDismissNotification tells a holder's other phones that a notification
// was answered on this one, so they take it off their lock screens too.
//
// POST /push/dismiss {"push_token", "key", "issued_at", "sig"}
//
// The request is signed with the key the phone's token is bound to
// (pushbind.go), over the token, the key and the time. A push token is not a
// secret, so without the signature anyone who learned one could clear a
// notification on the holder's other phones. Unsigned, badly signed or from a
// token with no proven key, the request reaches nobody.
//
// The phone names itself by its push token rather than a session: a holder taps
// a notification long after the wallet's half-hour session has lapsed, and a
// fresh one costs a Face ID. The token only selects the holder's other phones;
// each gets a silent push {type: "notification-dismiss", key} and removes the
// delivered notification with that key, which is all a caller can cause, and
// only for a request whose id it already knows. The answer is the same whether
// the token is known or not.
//
// Best effort: a phone that misses it clears the notification once it expires.
func (h *Handler) HandleDismissNotification(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PushToken string `json:"push_token"`
		Key       string `json:"key"`
		IssuedAt  int64  `json:"issued_at"`
		Sig       string `json:"sig"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil ||
		!dismissKey.MatchString(req.Key) || req.PushToken == "" || len(req.PushToken) > 256 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "push_token and key are required"})
		return
	}
	if !h.allow(w, r, "push-dismiss-ip", clientIP(r), dismissPerIP) ||
		!h.allow(w, r, "push-dismiss-token", req.PushToken, dismissPerToken) {
		return
	}
	var peers []store.PushPeer
	if dismissSigned(h.db.PushTokenBindKey(req.PushToken), req.PushToken, req.Key, req.IssuedAt, req.Sig) {
		peers = h.db.GetPushPeers(req.PushToken)
	}
	go func() {
		for _, p := range peers {
			if err := sendDismiss(context.Background(), h.db, p.UserID, push.Message{
				Token:      p.Token,
				Background: true,
				Data:       map[string]string{"type": "notification-dismiss", "key": req.Key},
			}); err != nil {
				log.Printf("[push] dismiss: %v", err)
			}
		}
	}()
	writeJSONStatus(w, http.StatusOK, map[string]string{"status": "ok"})
}

// pushDismissText is what a wallet signs to clear a notification elsewhere.
func pushDismissText(token, key string, issuedAt int64) []byte {
	return []byte("privasys-push-dismiss/v1\n" + token + "\n" + key + "\n" + strconv.FormatInt(issuedAt, 10))
}

// dismissSigned reports whether a dismissal is signed, recently, by the key
// its token is bound to.
func dismissSigned(bindPub, token, key string, issuedAt int64, sig string) bool {
	pub, okKey := pushBindKey(bindPub)
	raw, okSig := pushBindSig(sig)
	if !okKey || !okSig {
		return false
	}
	age := pushBinds.now().Sub(time.Unix(issuedAt, 0))
	return age > -pushRegisterWindow && age < pushRegisterWindow &&
		ed25519.Verify(pub, pushDismissText(token, key, issuedAt), raw)
}
