// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package appmessages is the app-neutral notification an attested app sends
// its users ("app-message"), and the short list that keeps the ones waiting on
// the holder.
//
// An app supplies three things, all optional except kind:
//
//   - kind, one value from a closed list owned here, which picks the banner
//     text. No app-written text reaches the banner, so nothing the app wrote
//     travels through Apple or Google in the clear.
//   - path, a path on the app's own host. Never a URL: the host is the one
//     the control plane verified for the app, and the wallet refuses a link
//     that would land anywhere else.
//   - presented, values someone presented to the holder, keyed by canonical
//     attribute keys. The wallet draws them with its own labels.
//
// The payload travels sealed to the holder's wallet key; the IdP reads only
// kind and the shape of path, and never stores a payload it could open.
//
// A request or an invitation waits on the holder, so the IdP keeps it for a
// few days: a push that never arrived, or was swiped away, still reaches the
// wallet, which lists it. The row holds the app's id, name and host, the
// kind, and the payload as sealed to the holder's key, or no payload when the
// holder has no sealing key yet.
package appmessages

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

// Type is the notification type the control plane forwards.
const Type = "app-message"

// TTL is how long a waiting message stays listed. Long enough to survive a
// weekend with the phone off; short enough that the list never becomes a
// record of what the holder was asked.
const TTL = 72 * time.Hour

// maxPerHolder bounds one holder's list, so an app sending in a loop cannot
// grow it without end. The oldest go first.
const maxPerHolder = 50

// maxPath bounds the path an app may link to.
const maxPath = 512

// kinds is the closed list. Each is tied to something the holder must act on
// or did themselves; there is deliberately no "update", the kind that turns
// into marketing.
var kinds = map[string]string{
	"request":    "You have a new request.",
	"invitation": "You have a new invitation.",
	"reminder":   "You have a reminder.",
	"response":   "There is a reply to your request.",
}

// genericBody is the banner for an unknown kind.
const genericBody = "You have a new notification."

// BannerBody returns the fixed banner text for kind.
func BannerBody(kind string) string {
	if b, ok := kinds[kind]; ok {
		return b
	}
	return genericBody
}

// KnownKind reports whether kind is on the closed list.
func KnownKind(kind string) bool {
	_, ok := kinds[kind]
	return ok
}

// Waits reports whether a message of this kind waits on the holder, and is
// therefore kept for the wallet to list.
func Waits(kind string) bool { return kind == "request" || kind == "invitation" }

// ErrPayload is returned for a payload that is not an app message.
var ErrPayload = errors.New("an app-message payload is an object with a kind, and an optional path starting with /")

// Parse reads the fields the IdP needs from a payload: the kind, after
// checking the path's shape. Everything else stays sealed and is the wallet's
// to read.
func Parse(payload json.RawMessage) (kind string, err error) {
	var p struct {
		Kind      string          `json:"kind"`
		Path      *string         `json:"path"`
		Presented json.RawMessage `json:"presented"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &p) != nil || p.Kind == "" {
		return "", ErrPayload
	}
	if p.Path != nil {
		path := *p.Path
		// A path on the app's host: rooted, bounded, and not "//host", which a
		// URL parser reads as another host.
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || len(path) > maxPath ||
			strings.ContainsAny(path, "\\\r\n\t ") {
			return "", ErrPayload
		}
	}
	if len(p.Presented) > 0 && string(p.Presented) != "null" {
		var m map[string]any
		if json.Unmarshal(p.Presented, &m) != nil {
			return "", ErrPayload
		}
	}
	return p.Kind, nil
}

// Message is one waiting message, as the wallet sees it.
type Message struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	AppID     string `json:"app_id,omitempty"`
	AppName   string `json:"app_name,omitempty"`
	AppHost   string `json:"app_host,omitempty"`
	Sealed    string `json:"sealed,omitempty"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// Store keeps the waiting messages.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New creates the table if needed and sweeps expired rows once an hour.
func New(db *sql.DB) (*Store, error) {
	s, err := open(db, time.Now)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			time.Sleep(time.Hour)
			s.sweep()
		}
	}()
	return s, nil
}

func open(db *sql.DB, now func() time.Time) (*Store, error) {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS app_messages (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			app_id     TEXT NOT NULL DEFAULT '',
			app_name   TEXT NOT NULL DEFAULT '',
			app_host   TEXT NOT NULL DEFAULT '',
			kind       TEXT NOT NULL,
			sealed     TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS app_messages_user ON app_messages(user_id, created_at);`); err != nil {
		return nil, err
	}
	return &Store{db: db, now: now}, nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Put records a waiting message for userID and returns its id.
func (s *Store) Put(userID string, m Message) (string, error) {
	if userID == "" || !Waits(m.Kind) {
		return "", nil
	}
	now := s.now()
	id := newID()
	if _, err := s.db.Exec(`INSERT INTO app_messages
		(id, user_id, app_id, app_name, app_host, kind, sealed, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, userID, m.AppID, m.AppName, m.AppHost, m.Kind, m.Sealed, now.Unix(), now.Add(TTL).Unix()); err != nil {
		return "", err
	}
	// Over the bound, the oldest go: the newest is the one the holder is
	// most likely waiting on.
	_, _ = s.db.Exec(`DELETE FROM app_messages WHERE user_id = ? AND id NOT IN (
		SELECT id FROM app_messages WHERE user_id = ? ORDER BY created_at DESC, id LIMIT ?)`,
		userID, userID, maxPerHolder)
	return id, nil
}

// ListFor returns userID's live messages, newest first.
func (s *Store) ListFor(userID string) []Message {
	rows, err := s.db.Query(`SELECT id, kind, app_id, app_name, app_host, sealed, created_at, expires_at
		FROM app_messages WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC, id`,
		userID, s.now().Unix())
	if err != nil {
		log.Printf("[appmessages] list: %v", err)
		return []Message{}
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		var m Message
		if rows.Scan(&m.ID, &m.Kind, &m.AppID, &m.AppName, &m.AppHost, &m.Sealed, &m.CreatedAt, &m.ExpiresAt) == nil {
			out = append(out, m)
		}
	}
	return out
}

// Remove drops one of userID's messages. Another holder's id is never touched.
func (s *Store) Remove(userID, id string) {
	_, _ = s.db.Exec(`DELETE FROM app_messages WHERE user_id = ? AND id = ?`, userID, id)
}

// RemoveByApp drops every message one app has waiting for userID: the holder
// removed the app, and nothing of it should still be listed.
func (s *Store) RemoveByApp(userID, appID string) {
	if s == nil {
		return
	}
	_, _ = s.db.Exec(`DELETE FROM app_messages WHERE user_id = ? AND (lower(app_id) = lower(?) OR replace(lower(app_id), '-', '') = lower(?))`,
		userID, appID, appID)
}

func (s *Store) sweep() {
	if _, err := s.db.Exec(`DELETE FROM app_messages WHERE expires_at <= ?`, s.now().Unix()); err != nil {
		log.Printf("[appmessages] sweep: %v", err)
	}
}

// Authenticate resolves the caller to a user id, or writes the error and
// returns "". The IdP's existing bearer check (wallet session or JWT) fits.
type Authenticate func(w http.ResponseWriter, r *http.Request) string

// HandleList serves GET /wallet/app-messages: the caller's waiting messages.
func HandleList(s *Store, auth Authenticate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth(w, r)
		if userID == "" {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string][]Message{"messages": s.ListFor(userID)})
	}
}

// HandleDismiss serves DELETE /wallet/app-messages/{id}, which the wallet
// calls once the holder has opened or dismissed one. Idempotent: 204 whether
// or not it was still listed.
func HandleDismiss(s *Store, auth Authenticate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth(w, r)
		if userID == "" {
			return
		}
		s.Remove(userID, r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	}
}
