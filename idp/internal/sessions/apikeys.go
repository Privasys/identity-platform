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

	// AppKeyClientID marks the session row behind a key addressed to one
	// app. Kept apart from API keys so a person's list of API keys is not
	// filled with the short keys their wallet makes.
	AppKeyClientID = "app-key"
	// AppKeyTTL is the lifetime of a key addressed to one app. Short: the
	// key reaches the app's own code, and the wallet makes another with one
	// biometric.
	AppKeyTTL = time.Hour
	// WalletToolClientID names the wallet as the tool an app key came
	// through: the token's azp, and the tool half of the subject when no
	// client stands for the app.
	WalletToolClientID = "privasys-wallet"
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
			// ClientID asks for a key that names the user as that client does
			// (per-app subjects): its own subject and its own audience. The
			// wallet calls Drive with one, so Drive sees the identifier its own
			// sign-in gives. Unknown or legacy clients get the account, as before.
			ClientID string `json:"client_id"`
			// AppID asks for a key addressed to that one app and nothing
			// else: see appKey.
			AppID string `json:"app_id"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
		label := strings.TrimSpace(body.Label)
		if label == "" {
			label = "API key"
		}
		if len(label) > 128 {
			label = label[:128]
		}
		if strings.TrimSpace(body.AppID) != "" {
			s.appKey(w, r, issuer, userID, label, body.AppID, body.Audience, body.ClientID)
			return
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
		subject := userID
		var asserted tokens.Asserted
		if c := strings.TrimSpace(body.ClientID); c != "" && s.sectorOf != nil {
			if sector := s.sectorOf(c); sector != "" {
				subject = issuer.SubjectFor(userID, sector)
				aud = c
			}
		}
		if subject == userID && tokens.IsPlatformAudience(aud) {
			// The platform keys accounts by this whatever subject is used.
			asserted.Account = userID
		}
		token, err := issuer.IssueAccessTokenAsserted(subject, aud, sid, nil, nil, asserted, APIKeyTTL)
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

// appKey mints a key for the wallet to present to ONE attested app, a
// resource service the holder is granting or reviewing access at.
//
// The wallet used to present its platform key there: an account-wide bearer
// the control plane accepts, good for a year, handed to whatever app was
// registered as a resource service. This key is the opposite on each count.
// Its audience is that app alone ("app:<id>"), so no other service accepts
// it. Its subject is the one the app's own sign-in gives the person, so the
// app learns nothing it could link them by. It names no account and carries
// no role, lives an hour, and says in azp that it came through the wallet.
//
// Only a wallet session may ask for one. An access token cannot: a relying
// party holding a person's token must not be able to turn it into a key for
// another app.
func (s *Store) appKey(w http.ResponseWriter, r *http.Request, issuer *tokens.Issuer, userID, label, appID, audience, clientID string) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer wallet:") {
		httpErr(w, http.StatusForbidden, "an app key is made from a wallet session")
		return
	}
	if strings.TrimSpace(clientID) != "" {
		httpErr(w, http.StatusBadRequest, "client_id cannot be given with app_id")
		return
	}
	if s.appSubject == nil {
		httpErr(w, http.StatusNotImplemented, "app keys are not available")
		return
	}
	id, sector, holderClient, err := s.appSubject(appID, WalletToolClientID)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	aud := "app:" + id
	// The audience is the app's and no other: a platform audience, or any
	// audience but this one, is refused when the key is for an app.
	if a := strings.TrimSpace(audience); a != "" && a != aud {
		httpErr(w, http.StatusBadRequest, "the audience of an app key is the app's own")
		return
	}
	subject := issuer.SubjectFor(userID, sector)
	sid := NewSID()
	if _, err := s.Create(sid, userID, AppKeyClientID, label, AppKeyTTL); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The row that lets the platform find the account behind this subject
	// (who pays, who to notify), as a sign-in to the app would have left it.
	if err := s.RecordHolder(subject, holderClient, userID); err != nil {
		_ = s.Revoke(sid)
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, err := issuer.IssueAccessTokenAsserted(subject, aud, sid, nil, nil,
		tokens.Asserted{AuthorizedParty: WalletToolClientID, Actor: WalletToolClientID}, AppKeyTTL)
	if err != nil {
		_ = s.Revoke(sid)
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"sid":        sid,
		"label":      label,
		"token":      token,
		"audience":   aud,
		"expires_at": time.Now().Add(AppKeyTTL).Unix(),
	})
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
