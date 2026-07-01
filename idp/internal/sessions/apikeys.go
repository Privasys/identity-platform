// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// API keys are long-lived access tokens (at+jwt) bound to a session row, so
// they reuse the whole session/revocation machinery: an API key is listable
// (GET /api-keys), revocable (POST /sessions/{sid}/revoke), and a resource
// server rejects it once its sid is revoked. No separate credential type.
package sessions

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

const (
	// APIKeyClientID marks a session row that backs an API key, so keys are
	// listed and managed separately from interactive login sessions.
	APIKeyClientID = "api-key"
	// APIKeyTTL is a minted API key's lifetime. Long, but revocable via the
	// session's sid.
	APIKeyTTL = 365 * 24 * time.Hour
)

// ListAPIKeysByUser returns the user's non-revoked API-key sessions,
// most-recently-created first. The human label is stored in device_id.
func (s *Store) ListAPIKeysByUser(userID string) ([]*Session, error) {
	rows, err := s.db.Query(`
		SELECT sid, user_id, client_id, device_id, created_at, last_seen_at, expires_at
		  FROM sessions
		 WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL
		 ORDER BY created_at DESC`, userID, APIKeyClientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		var ss Session
		if err := rows.Scan(&ss.SID, &ss.UserID, &ss.ClientID, &ss.DeviceID,
			&ss.CreatedAt, &ss.LastSeenAt, &ss.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, &ss)
	}
	return out, rows.Err()
}

// ListRevokedSince returns session ids revoked at or after `since` (unix
// seconds). Resource servers (e.g. the confidential-ai enclave) poll this to
// reject tokens whose sid was revoked, without a per-request callout. Revoked
// sids are opaque and already dead, so the list is not sensitive.
func (s *Store) ListRevokedSince(since int64) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT sid FROM sessions
		 WHERE revoked_at IS NOT NULL AND revoked_at >= ?
		 ORDER BY revoked_at`, time.Unix(since, 0).UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return nil, err
		}
		out = append(out, sid)
	}
	return out, rows.Err()
}

// HandleCreateAPIKey mints an API key for the authenticated user.
//
//	POST /api-keys        {"label": "...", "audience": "..."}
//	Authorization: Bearer <access_token>
//	-> 201 {"sid","label","token","expires_at"}   (token shown ONCE)
func (s *Store) HandleCreateAPIKey(issuer *tokens.Issuer, defaultAudience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, err := s.authBearer(r, issuer)
		if err != nil {
			httpUnauth(w, err.Error())
			return
		}
		var body struct {
			Label    string `json:"label"`
			Audience string `json:"audience"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
		label := strings.TrimSpace(body.Label)
		if label == "" {
			label = "API key"
		}
		if len(label) > 128 {
			label = label[:128]
		}
		aud := strings.TrimSpace(body.Audience)
		if aud == "" {
			aud = defaultAudience
		}
		sid := NewSID()
		if _, err := s.Create(sid, userID, APIKeyClientID, label, APIKeyTTL); err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		token, err := issuer.IssueAccessTokenWithTTL(userID, aud, sid, nil, nil, APIKeyTTL)
		if err != nil {
			_ = s.Revoke(sid) // never leave a session with no usable key
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"sid":        sid,
			"label":      label,
			"token":      token,
			"expires_at": time.Now().Add(APIKeyTTL).Unix(),
		})
	}
}

// HandleListAPIKeys lists the authenticated user's API keys (metadata only;
// the token is never retrievable after creation).
//
//	GET /api-keys
//	Authorization: Bearer <access_token>
func (s *Store) HandleListAPIKeys(issuer *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, err := s.authBearer(r, issuer)
		if err != nil {
			httpUnauth(w, err.Error())
			return
		}
		list, err := s.ListAPIKeysByUser(userID)
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]map[string]any, 0, len(list))
		for _, ss := range list {
			out = append(out, map[string]any{
				"sid":        ss.SID,
				"label":      ss.DeviceID,
				"created_at": ss.CreatedAt.Unix(),
				"expires_at": ss.ExpiresAt.Unix(),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_keys": out})
	}
}

// HandleListRevoked returns session ids revoked at or after ?since=<unix>, for
// resource servers to poll. Unauthenticated: revoked sids are opaque, dead
// identifiers, and returning them lets a verifier reject revoked tokens without
// a per-request callout.
//
//	GET /sessions/revoked?since=<unix seconds>
//	-> {"revoked":["sid",...],"now":<unix>}
func (s *Store) HandleListRevoked() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var since int64
		if v := r.URL.Query().Get("since"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				since = n
			}
		}
		list, err := s.ListRevokedSince(since)
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked": list, "now": time.Now().Unix()})
	}
}
