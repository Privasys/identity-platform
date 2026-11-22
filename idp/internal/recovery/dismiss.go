// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package recovery

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/Privasys/idp/internal/push"
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
// POST /push/dismiss {"push_token": "<this phone's>", "key": "<hash>"}
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
	peers := h.db.GetPushPeers(req.PushToken)
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
