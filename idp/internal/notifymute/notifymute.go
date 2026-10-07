// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package notifymute lets a holder silence one app's notifications.
//
// What it keeps is the smallest record that can do the job: one row per
// (identity, app) pair the holder chose to silence, and nothing for any app
// they did not. The row is an HMAC of the pair under a key derived from the
// IdP's signing key, never the pair itself, so the table read on its own (a
// backup, a leak) says nothing about who uses what. Whoever holds the key can
// test a given pair, which the relay has to be able to do; it cannot list an
// identity's apps without trying them.
//
// It records a choice the holder made, not their usage. That distinction is
// the reason it exists in this form: the IdP deliberately keeps no log of
// which apps an identity signs in to.
//
// It silences notifications an app sends, and never the ones that carry a
// request the holder must answer: an access request (capability-request)
// always arrives. Sign-in, vault approvals, attribute step-ups and guardian
// requests do not pass through the app relay at all, so nothing here can
// reach them.
package notifymute

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
)

// alwaysDelivered names the app-sent types a mute never silences: each asks
// the holder for a decision, and silencing it would leave the asking app
// waiting on someone who cannot see the question.
var alwaysDelivered = map[string]bool{
	"capability-request": true,
	// Someone asking for the holder's files (a Drive share link that the
	// owner approves person by person): they wait on the holder's answer.
	"share-request": true,
}

// appIDShape is an attested app id as the control plane forwards it: a
// lowercase dashed UUID (OID 4.1).
var appIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Store is what this package needs from the database.
type Store interface {
	MuteNotify(pairHash string) error
	UnmuteNotify(pairHash string) error
	IsNotifyMuted(pairHash string) bool
}

// Authenticate resolves the caller to a user id, or writes the error and
// returns "". The IdP's existing bearer check (wallet session or JWT) fits.
type Authenticate func(w http.ResponseWriter, r *http.Request) string

// Service holds the key and the store. The relay needs only Silenced; the
// wallet-facing handlers take the bearer check when they are registered.
type Service struct {
	db  Store
	key []byte
}

// New returns a service keyed by `key`, which should come from
// tokens.Issuer.DeriveSecret("notify-mute"). Rotating the signing key changes
// it, so every mute lapses; the wallet keeps its own list and a holder who
// notices can switch the app off again.
func New(db Store, key []byte) *Service {
	return &Service{db: db, key: key}
}

func (s *Service) pairHash(userID, appID string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(userID))
	mac.Write([]byte{0}) // neither half can contain NUL, so the pair is unambiguous
	mac.Write([]byte(strings.ToLower(appID)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Silenced reports whether a notification of type `typ` from `appID` to
// `userID` should be dropped because the holder muted that app. A type the
// holder must answer is never silenced.
func (s *Service) Silenced(userID, appID, typ string) bool {
	if s == nil || alwaysDelivered[typ] || userID == "" || appID == "" {
		return false
	}
	return s.db.IsNotifyMuted(s.pairHash(userID, appID))
}

// HandleMute serves PUT /wallet/notify-mutes/{app_id}: silence that app for
// the calling identity. 204, idempotent.
func (s *Service) HandleMute(auth Authenticate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.handle(w, r, auth, s.db.MuteNotify)
	}
}

// HandleUnmute serves DELETE /wallet/notify-mutes/{app_id}: hear from that
// app again. 204, idempotent.
func (s *Service) HandleUnmute(auth Authenticate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.handle(w, r, auth, s.db.UnmuteNotify)
	}
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request, auth Authenticate, apply func(string) error) {
	userID := auth(w, r)
	if userID == "" {
		return
	}
	appID := strings.ToLower(r.PathValue("app_id"))
	if !appIDShape.MatchString(appID) {
		http.Error(w, `{"error":"app_id must be a UUID"}`, http.StatusBadRequest)
		return
	}
	if err := apply(s.pairHash(userID, appID)); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
