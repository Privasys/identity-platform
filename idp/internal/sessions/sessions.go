// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package sessions implements the unified per-(user, app, device) session
// row backing every JWT issued by the IdP. Each session has a stable
// `sid` that is embedded in id/access/refresh tokens and that the user
// can revoke from the wallet. See `.operations/identity-platform/
// session-plan.md` §2.
//
// The store is intentionally tiny and append-mostly: rows are created on
// first sign-in (or on first refresh-token rotation for legacy sessions
// minted before this package shipped), updated on each refresh, and
// soft-deleted on revoke.
package sessions

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// WalletSessionResolver resolves a short-lived wallet session token
// (issued by `/fido2/*/complete`) to a user_id. The wallet uses these
// tokens as its primary auth credential, so the session-management
// endpoints accept them in addition to OIDC access tokens.
type WalletSessionResolver func(token string) (string, bool)

// ErrNotFound is returned by lookups that match no row.
var ErrNotFound = errors.New("session not found")

// ErrRevoked is returned when a token presents a sid that has been
// revoked by the user. Callers must reject the token on this error.
var ErrRevoked = errors.New("session revoked")

// Session is a row in the unified sessions table.
type Session struct {
	SID         string
	UserID      string
	ClientID    string
	DeviceID    string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

// Store wraps the IdP DB with session-table operations.
type Store struct {
	db            *store.DB
	walletSession WalletSessionResolver
}

// SetWalletSessionResolver wires the FIDO2 wallet-session lookup into
// the auth path of /sessions/me and /sessions/{sid}/revoke. Optional
// — when nil only OIDC access tokens are accepted.
func (s *Store) SetWalletSessionResolver(r WalletSessionResolver) {
	s.walletSession = r
}

// New constructs a Store and ensures the sessions table exists.
func New(db *store.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			sid          TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			client_id    TEXT NOT NULL,
			device_id    TEXT NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at   DATETIME NOT NULL,
			revoked_at   DATETIME
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_user
			ON sessions(user_id, revoked_at);
	`)
	if err != nil {
		return nil, fmt.Errorf("create sessions table: %w", err)
	}
	return &Store{db: db}, nil
}

// NewSID returns a fresh, URL-safe session id (32 random bytes,
// base64url, no padding — distinct syntactic space from FIDO2 session
// tokens which are 64-char hex).
func NewSID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Should never happen on supported platforms; panic so we don't
		// silently mint deterministic sids.
		panic(fmt.Sprintf("sessions: rand.Read: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Create inserts a new session row and returns it.
func (s *Store) Create(sid, userID, clientID, deviceID string, ttl time.Duration) (*Session, error) {
	if sid == "" {
		sid = NewSID()
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	_, err := s.db.Exec(
		`INSERT INTO sessions (sid, user_id, client_id, device_id,
			created_at, last_seen_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sid, userID, clientID, deviceID, now, now, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}
	return &Session{
		SID: sid, UserID: userID, ClientID: clientID, DeviceID: deviceID,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: expiresAt,
	}, nil
}

// Touch updates last_seen_at and (optionally) extends expires_at to
// `now + ttl`. Used on refresh-token rotation.
func (s *Store) Touch(sid string, extend time.Duration) error {
	now := time.Now().UTC()
	var res sql.Result
	var err error
	if extend > 0 {
		res, err = s.db.Exec(
			`UPDATE sessions
			    SET last_seen_at = ?, expires_at = ?
			  WHERE sid = ? AND revoked_at IS NULL`,
			now, now.Add(extend), sid,
		)
	} else {
		res, err = s.db.Exec(
			`UPDATE sessions SET last_seen_at = ?
			  WHERE sid = ? AND revoked_at IS NULL`,
			now, sid,
		)
	}
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Either unknown sid or revoked. Distinguish.
		var revoked sql.NullTime
		if err := s.db.QueryRow(`SELECT revoked_at FROM sessions WHERE sid = ?`, sid).Scan(&revoked); err != nil {
			return ErrNotFound
		}
		if revoked.Valid {
			return ErrRevoked
		}
		return ErrNotFound
	}
	return nil
}

// Get returns a session by sid (revoked rows included; check Revoked()).
func (s *Store) Get(sid string) (*Session, error) {
	var sess Session
	var revoked sql.NullTime
	err := s.db.QueryRow(
		`SELECT sid, user_id, client_id, device_id,
		        created_at, last_seen_at, expires_at, revoked_at
		   FROM sessions WHERE sid = ?`,
		sid,
	).Scan(&sess.SID, &sess.UserID, &sess.ClientID, &sess.DeviceID,
		&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &revoked)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if revoked.Valid {
		t := revoked.Time
		sess.RevokedAt = &t
	}
	return &sess, nil
}

// IsActive returns true iff the sid exists, is not revoked, and is not
// expired. Used by every token-verification path.
func (s *Store) IsActive(sid string) bool {
	if sid == "" {
		return true // legacy tokens without a sid claim — treat as active
	}
	sess, err := s.Get(sid)
	if err != nil {
		return false
	}
	if sess.RevokedAt != nil {
		return false
	}
	if time.Now().After(sess.ExpiresAt) {
		return false
	}
	return true
}

// ListByUser returns the user's non-revoked sessions, most-recently-active
// first.
func (s *Store) ListByUser(userID string) ([]*Session, error) {
	rows, err := s.db.Query(
		`SELECT sid, user_id, client_id, device_id,
		        created_at, last_seen_at, expires_at
		   FROM sessions
		  WHERE user_id = ? AND revoked_at IS NULL
		  ORDER BY last_seen_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.SID, &sess.UserID, &sess.ClientID, &sess.DeviceID,
			&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, &sess)
	}
	return out, rows.Err()
}

// Revoke soft-deletes a session. Subsequent IsActive checks will return
// false; subsequent refresh-token rotations against the linked refresh
// row should be rejected by the caller.
func (s *Store) Revoke(sid string) error {
	now := time.Now().UTC()
	res, err := s.db.Exec(
		`UPDATE sessions SET revoked_at = ?
		  WHERE sid = ? AND revoked_at IS NULL`,
		now, sid,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CleanupExpired hard-deletes rows whose expires_at + 30d has passed.
// Revoked rows are kept for the same window so audit queries still work.
func (s *Store) CleanupExpired() {
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, cutoff)
}

// --- HTTP handlers --------------------------------------------------

// HandleListMine returns the current user's active sessions.
//
//	GET /sessions/me
//	Authorization: Bearer <access_token>
func (s *Store) HandleListMine(issuer *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, err := s.authBearer(r, issuer)
		if err != nil {
			httpUnauth(w, err.Error())
			return
		}
		list, err := s.ListByUser(userID)
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]map[string]any, 0, len(list))
		for _, sess := range list {
			out = append(out, map[string]any{
				"sid":          sess.SID,
				"client_id":    sess.ClientID,
				"device_id":    sess.DeviceID,
				"created_at":   sess.CreatedAt.Unix(),
				"last_seen_at": sess.LastSeenAt.Unix(),
				"expires_at":   sess.ExpiresAt.Unix(),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
	}
}

// HandleRevoke revokes a session id. The caller must present an access
// token whose `sub` matches the session's user_id (so a user can only
// revoke their own sessions).
//
//	POST /sessions/{sid}/revoke
//	Authorization: Bearer <access_token>
func (s *Store) HandleRevoke(issuer *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, err := s.authBearer(r, issuer)
		if err != nil {
			httpUnauth(w, err.Error())
			return
		}
		sid := r.PathValue("sid")
		if sid == "" {
			httpErr(w, http.StatusBadRequest, "sid required")
			return
		}
		sess, err := s.Get(sid)
		if errors.Is(err, ErrNotFound) {
			httpErr(w, http.StatusNotFound, "session not found")
			return
		}
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if sess.UserID != userID {
			// Don't leak existence of other users' sessions.
			httpErr(w, http.StatusNotFound, "session not found")
			return
		}
		if err := s.Revoke(sid); err != nil && !errors.Is(err, ErrNotFound) {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked": sid})
	}
}

// authBearer extracts and verifies a Bearer token, returning
// (sub, sid). Accepts two forms:
//   - "Bearer wallet:<token>" — short-lived wallet session token
//     issued by `/fido2/*/complete`. sid is returned empty.
//   - "Bearer <jwt>"          — OIDC access token. sid is the `sid`
//     claim, possibly empty for legacy tokens.
func (s *Store) authBearer(r *http.Request, issuer *tokens.Issuer) (string, string, error) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || !strings.HasPrefix(auth, "Bearer ") {
		return "", "", errors.New("bearer token required")
	}
	token := auth[7:]
	if strings.HasPrefix(token, "wallet:") && s.walletSession != nil {
		walletToken := strings.TrimPrefix(token, "wallet:")
		if userID, ok := s.walletSession(walletToken); ok {
			return userID, "", nil
		}
		return "", "", errors.New("invalid or expired wallet session")
	}
	claims, err := issuer.VerifyAccessToken(token)
	if err != nil {
		return "", "", err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", "", errors.New("token missing sub")
	}
	sid, _ := claims["sid"].(string)
	return sub, sid, nil
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func httpUnauth(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	httpErr(w, http.StatusUnauthorized, msg)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
