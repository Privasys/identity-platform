// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package spend implements the user's standing consent for an app to spend
// their platform credits, and the sender-constrained SPEND TOKEN an app
// presents to every service it calls on that user's behalf.
//
// The model (acting-subject plan v2, 2026-09-09):
//
//   - The user consents ONCE per app, in the wallet at sign-in or on
//     privasys.id/account: "App X may spend my credits, up to N per month".
//     The consent is backed by a session row (client_id "spend:<app>") so the
//     ordinary session machinery revokes it: the user revokes the spender, the
//     sid lands on the revoked feed every callee already polls, and the next
//     token request is refused.
//   - The app fetches a spend token per signed-in user (POST /spend/token),
//     authenticating as the app with a private-key JWT signed by a key it
//     generated at boot and publishes at its well-known JWKS. The token binds
//     that key in `cnf`, so a leaked token is inert without the key.
//   - On every call the app attaches the token plus a per-callee proof signed
//     with the same key; the callee's runtime verifies both and asserts the
//     paying user to the app. The credit service never sees a token.
//
// Nothing here consults an allowed-caller list, a platform list or an OS
// release: billing is independent of pinning.
package spend

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Privasys/idp/internal/sessions"
	"github.com/Privasys/idp/internal/store"
)

// ErrNotFound is returned when a user has no (live) consent for an app.
var ErrNotFound = errors.New("spend: no consent for this app")

// ConsentTTL is how long a spend consent stays valid without renewal. The
// backing session row expires with it; a sign-in that reaffirms the consent
// extends it.
const ConsentTTL = 365 * 24 * time.Hour

// SessionClientPrefix marks the session rows that back spend consents, so
// they list and revoke like any other session but never collide with an
// OIDC client id.
const SessionClientPrefix = "spend:"

// appIDRe is the undashed lowercase hex form of a platform app id (OID
// 3.6). A spender that is not a platform app (a non-enclave relying party)
// is identified by its OIDC client id instead; see Handler.resolveKeys.
var appIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// IsPlatformAppID reports whether s is a platform app id (32 hex).
func IsPlatformAppID(s string) bool { return appIDRe.MatchString(s) }

// NormaliseAppID lowercases and strips the dashes of a platform app id;
// any other identifier (an OIDC client id) is returned trimmed.
func NormaliseAppID(s string) string {
	s = strings.TrimSpace(s)
	undashed := strings.ToLower(strings.ReplaceAll(s, "-", ""))
	if appIDRe.MatchString(undashed) {
		return undashed
	}
	return s
}

// Consent is one user's standing authorisation for one app to spend.
type Consent struct {
	UserID    string     `json:"-"`
	AppID     string     `json:"app_id"`
	AppHost   string     `json:"app_host,omitempty"`
	AppName   string     `json:"app_name,omitempty"`
	Cap       int64      `json:"cap"` // credits per calendar month; 0 = no cap
	SID       string     `json:"sid"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Store persists consents beside the sessions that back them.
type Store struct {
	db       *store.DB
	sessions *sessions.Store
}

// NewStore creates the consent table if needed.
func NewStore(db *store.DB, sess *sessions.Store) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS spend_consents (
			user_id    TEXT NOT NULL,
			app_id     TEXT NOT NULL,
			app_host   TEXT NOT NULL DEFAULT '',
			app_name   TEXT NOT NULL DEFAULT '',
			cap        INTEGER NOT NULL DEFAULT 0,
			sid        TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at DATETIME,
			PRIMARY KEY (user_id, app_id)
		);
		CREATE INDEX IF NOT EXISTS idx_spend_consents_sid ON spend_consents(sid);
	`)
	if err != nil {
		return nil, fmt.Errorf("create spend_consents: %w", err)
	}
	return &Store{db: db, sessions: sess}, nil
}

// Grant records (or renews) the user's consent for appID under cap. A fresh
// consent, or one that was revoked, gets a new backing session; a live one
// keeps its sid (so tokens already issued stay valid) and only the cap and
// display fields move.
func (s *Store) Grant(userID, appID, appHost, appName string, cap int64) (*Consent, error) {
	if userID == "" || appID == "" {
		return nil, errors.New("spend: user and app required")
	}
	if cap < 0 {
		return nil, errors.New("spend: cap must not be negative")
	}
	now := time.Now().UTC()
	existing, err := s.get(userID, appID, true)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if existing != nil && existing.RevokedAt == nil && s.sessions.IsActive(existing.SID) {
		_ = s.sessions.Touch(existing.SID, ConsentTTL)
		if appHost == "" {
			appHost = existing.AppHost
		}
		if appName == "" {
			appName = existing.AppName
		}
		if _, err := s.db.Exec(`UPDATE spend_consents
			SET cap = ?, app_host = ?, app_name = ?, updated_at = ?
			WHERE user_id = ? AND app_id = ?`,
			cap, appHost, appName, now, userID, appID); err != nil {
			return nil, fmt.Errorf("update consent: %w", err)
		}
		return s.get(userID, appID, false)
	}
	sess, err := s.sessions.Create("", userID, SessionClientPrefix+appID, appHost, ConsentTTL)
	if err != nil {
		return nil, fmt.Errorf("create consent session: %w", err)
	}
	if existing == nil {
		_, err = s.db.Exec(`INSERT INTO spend_consents
			(user_id, app_id, app_host, app_name, cap, sid, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			userID, appID, appHost, appName, cap, sess.SID, now, now)
	} else {
		_, err = s.db.Exec(`UPDATE spend_consents
			SET cap = ?, app_host = ?, app_name = ?, sid = ?, updated_at = ?, revoked_at = NULL
			WHERE user_id = ? AND app_id = ?`,
			cap, appHost, appName, sess.SID, now, userID, appID)
	}
	if err != nil {
		return nil, fmt.Errorf("write consent: %w", err)
	}
	return s.get(userID, appID, false)
}

// Get returns the user's LIVE consent for appID (not revoked, session
// active), or ErrNotFound.
func (s *Store) Get(userID, appID string) (*Consent, error) {
	c, err := s.get(userID, appID, false)
	if err != nil {
		return nil, err
	}
	if !s.sessions.IsActive(c.SID) {
		return nil, ErrNotFound
	}
	return c, nil
}

func (s *Store) get(userID, appID string, includeRevoked bool) (*Consent, error) {
	row := s.db.QueryRow(`SELECT user_id, app_id, app_host, app_name, cap, sid,
			created_at, updated_at, revoked_at
		FROM spend_consents WHERE user_id = ? AND app_id = ?`, userID, appID)
	c, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if c.RevokedAt != nil && !includeRevoked {
		return nil, ErrNotFound
	}
	return c, nil
}

// List returns the user's live consents, most recently updated first.
func (s *Store) List(userID string) ([]*Consent, error) {
	rows, err := s.db.Query(`SELECT user_id, app_id, app_host, app_name, cap, sid,
			created_at, updated_at, revoked_at
		FROM spend_consents WHERE user_id = ? AND revoked_at IS NULL
		ORDER BY updated_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Consent
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, err
		}
		if !s.sessions.IsActive(c.SID) {
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Revoke ends the user's consent for appID: the backing session is revoked
// (so it reaches every callee's revoked feed) and the row is marked.
func (s *Store) Revoke(userID, appID string) error {
	c, err := s.get(userID, appID, false)
	if err != nil {
		return err
	}
	if err := s.sessions.Revoke(c.SID); err != nil && !errors.Is(err, sessions.ErrNotFound) {
		return err
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(`UPDATE spend_consents SET revoked_at = ?, updated_at = ?
		WHERE user_id = ? AND app_id = ?`, now, now, userID, appID)
	return err
}

// RevokeBySID is the hook for the generic session revoke path: when the
// user revokes a "spend:<app>" session from the sessions list, the consent
// row follows.
func (s *Store) RevokeBySID(sid string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE spend_consents SET revoked_at = ?, updated_at = ?
		WHERE sid = ? AND revoked_at IS NULL`, now, now, sid)
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(r scanner) (*Consent, error) {
	var c Consent
	var revoked sql.NullTime
	if err := r.Scan(&c.UserID, &c.AppID, &c.AppHost, &c.AppName, &c.Cap, &c.SID,
		&c.CreatedAt, &c.UpdatedAt, &revoked); err != nil {
		return nil, err
	}
	if revoked.Valid {
		t := revoked.Time
		c.RevokedAt = &t
	}
	return &c, nil
}
