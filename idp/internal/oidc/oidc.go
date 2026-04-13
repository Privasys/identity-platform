// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package oidc implements the OIDC authorization server endpoints.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// HandleDiscovery returns the OIDC discovery document.
func HandleDiscovery(issuerURL string) http.HandlerFunc {
	doc := map[string]interface{}{
		"issuer":                                issuerURL,
		"authorization_endpoint":                issuerURL + "/authorize",
		"token_endpoint":                        issuerURL + "/token",
		"userinfo_endpoint":                     issuerURL + "/userinfo",
		"jwks_uri":                              issuerURL + "/jwks",
		"registration_endpoint":                 issuerURL + "/clients",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "name", "email", "email_verified", "picture",
			"attestation_level", "auth_time", "iss", "aud", "exp", "iat",
		},
	}

	body, _ := json.MarshalIndent(doc, "", "  ")

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(body)
	}
}

// --- Authorization Code Store ---

// AuthCode represents a pending authorization code.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	UserID              string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
}

// CodeStore manages short-lived authorization codes.
type CodeStore struct {
	mu    sync.Mutex
	codes map[string]*AuthCode
}

// NewCodeStore creates a new in-memory code store.
func NewCodeStore() *CodeStore {
	cs := &CodeStore{codes: make(map[string]*AuthCode)}
	// Cleanup expired codes every minute.
	go func() {
		for {
			time.Sleep(time.Minute)
			cs.cleanup()
		}
	}()
	return cs
}

// Create generates and stores a new authorization code.
func (cs *CodeStore) Create(ac *AuthCode) string {
	b := make([]byte, 32)
	rand.Read(b)
	code := base64.RawURLEncoding.EncodeToString(b)

	ac.Code = code
	ac.ExpiresAt = time.Now().Add(5 * time.Minute)

	cs.mu.Lock()
	cs.codes[code] = ac
	cs.mu.Unlock()

	return code
}

// Consume retrieves and deletes an authorization code (single-use).
func (cs *CodeStore) Consume(code string) (*AuthCode, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	ac, ok := cs.codes[code]
	if !ok {
		return nil, false
	}
	delete(cs.codes, code)

	if time.Now().After(ac.ExpiresAt) {
		return nil, false
	}
	return ac, true
}

func (cs *CodeStore) cleanup() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := time.Now()
	for k, v := range cs.codes {
		if now.After(v.ExpiresAt) {
			delete(cs.codes, k)
		}
	}
}

// --- Session Store ---

// AuthSession tracks a pending authorization request (browser waiting for wallet approval).
type AuthSession struct {
	SessionID           string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	CreatedAt           time.Time
	ExpiresAt           time.Time

	// Set when the wallet completes FIDO2 authentication.
	Authenticated bool
	UserID        string
	AuthCode      string // The authorization code to deliver to the browser.
}

// SessionStore manages pending authorization sessions.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*AuthSession
}

// NewSessionStore creates a new in-memory session store.
func NewSessionStore() *SessionStore {
	ss := &SessionStore{sessions: make(map[string]*AuthSession)}
	go func() {
		for {
			time.Sleep(time.Minute)
			ss.cleanup()
		}
	}()
	return ss
}

// Create stores a new authorization session.
func (ss *SessionStore) Create(s *AuthSession) {
	ss.mu.Lock()
	ss.sessions[s.SessionID] = s
	ss.mu.Unlock()
}

// Get retrieves a session by ID.
func (ss *SessionStore) Get(id string) (*AuthSession, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[id]
	if !ok || time.Now().After(s.ExpiresAt) {
		return nil, false
	}
	return s, true
}

// Complete marks a session as authenticated and stores the auth code.
func (ss *SessionStore) Complete(sessionID, userID, authCode string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[sessionID]
	if !ok {
		return false
	}
	s.Authenticated = true
	s.UserID = userID
	s.AuthCode = authCode
	return true
}

func (ss *SessionStore) cleanup() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	now := time.Now()
	for k, v := range ss.sessions {
		if now.After(v.ExpiresAt) {
			delete(ss.sessions, k)
		}
	}
}

// --- /authorize ---

// HandleAuthorize handles the OIDC authorization request.
// Returns a JSON response with a session ID and QR payload for the wallet.
func HandleAuthorize(reg *clients.Registry, sessions *SessionStore, issuerURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		clientID := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		responseType := q.Get("response_type")
		scope := q.Get("scope")
		state := q.Get("state")
		nonce := q.Get("nonce")
		codeChallenge := q.Get("code_challenge")
		codeChallengeMethod := q.Get("code_challenge_method")

		// Validate response_type.
		if responseType != "code" {
			errorResponse(w, http.StatusBadRequest, "unsupported_response_type",
				"Only 'code' response type is supported")
			return
		}

		// Validate client.
		client, err := reg.Get(clientID)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
			return
		}

		// Validate redirect_uri.
		if !client.ValidRedirectURI(redirectURI) {
			errorResponse(w, http.StatusBadRequest, "invalid_request",
				"redirect_uri does not match any registered URI")
			return
		}

		// PKCE is required.
		if codeChallenge == "" {
			errorResponse(w, http.StatusBadRequest, "invalid_request",
				"code_challenge is required (PKCE)")
			return
		}
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}
		if codeChallengeMethod != "S256" {
			errorResponse(w, http.StatusBadRequest, "invalid_request",
				"Only S256 code_challenge_method is supported")
			return
		}

		// Generate session ID.
		sessionID := generateID()

		session := &AuthSession{
			SessionID:           sessionID,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scope:               scope,
			State:               state,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			CreatedAt:           time.Now(),
			ExpiresAt:           time.Now().Add(5 * time.Minute),
		}
		sessions.Create(session)

		// Return the session info for the browser to render a QR code.
		// The browser SDK knows how to display this.
		qrPayload := map[string]string{
			"origin":    issuerURL,
			"sessionId": sessionID,
			"rpId":      "privasys.id",
			"brokerUrl": "wss://relay.privasys.org/relay",
			"type":      "oidc-authorize",
		}

		resp := map[string]interface{}{
			"session_id": sessionID,
			"qr_payload": qrPayload,
			"expires_in": 300,
			"poll_url":   issuerURL + "/session/status?session_id=" + sessionID,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// --- /session/status ---

// HandleSessionStatus allows the browser to poll for session completion.
func HandleSessionStatus(sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "session_id required")
			return
		}

		session, ok := sessions.Get(sessionID)
		if !ok {
			errorResponse(w, http.StatusNotFound, "invalid_request", "Session not found or expired")
			return
		}

		resp := map[string]interface{}{
			"authenticated": session.Authenticated,
		}
		if session.Authenticated {
			resp["redirect_uri"] = session.RedirectURI +
				"?code=" + url.QueryEscape(session.AuthCode) +
				"&state=" + url.QueryEscape(session.State)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// --- /token ---

// HandleToken handles the OIDC token exchange (authorization code → tokens).
func HandleToken(reg *clients.Registry, codes *CodeStore, issuer *tokens.Issuer, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "Cannot parse form")
			return
		}

		grantType := r.FormValue("grant_type")
		if grantType != "authorization_code" {
			errorResponse(w, http.StatusBadRequest, "unsupported_grant_type",
				"Only 'authorization_code' is supported")
			return
		}

		code := r.FormValue("code")
		redirectURI := r.FormValue("redirect_uri")
		codeVerifier := r.FormValue("code_verifier")
		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")

		// Validate client_secret for confidential clients.
		ok, err := reg.VerifySecret(clientID, clientSecret)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client")
			return
		}
		if !ok {
			errorResponse(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
			return
		}

		// Consume the authorization code (single-use).
		ac, ok := codes.Consume(code)
		if !ok {
			errorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired authorization code")
			return
		}

		// Validate client_id matches.
		if ac.ClientID != clientID {
			errorResponse(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
			return
		}

		// Validate redirect_uri matches.
		if ac.RedirectURI != redirectURI {
			errorResponse(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		}

		// Verify PKCE code_verifier.
		if !verifyPKCE(ac.CodeChallenge, codeVerifier) {
			errorResponse(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}

		// Look up user profile.
		user, err := getUserProfile(db, ac.UserID)
		if err != nil {
			log.Printf("token: user lookup failed: %v", err)
			errorResponse(w, http.StatusInternalServerError, "server_error", "User lookup failed")
			return
		}

		// Issue ID token.
		idToken, err := issuer.IssueIDToken(tokens.IDTokenClaims{
			Subject:          ac.UserID,
			Email:            user.Email,
			Name:             user.DisplayName,
			Picture:          user.AvatarURL,
			AttestationLevel: "verified",
			Audience:         ac.ClientID,
			Nonce:            ac.Nonce,
			AuthTime:         ac.AuthTime,
		})
		if err != nil {
			log.Printf("token: ID token issuance failed: %v", err)
			errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
			return
		}

		// Issue access token.
		accessToken, err := issuer.IssueAccessToken(ac.UserID, ac.ClientID)
		if err != nil {
			log.Printf("token: access token issuance failed: %v", err)
			errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
			return
		}

		resp := map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
			"scope":        ac.Scope,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		json.NewEncoder(w).Encode(resp)
	}
}

// --- /userinfo ---

// HandleUserInfo returns user profile claims for authenticated requests.
func HandleUserInfo(issuer *tokens.Issuer, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token.
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			w.Header().Set("WWW-Authenticate", "Bearer")
			errorResponse(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
			return
		}
		tokenStr := auth[7:]

		// Verify the access token.
		claims, err := issuer.VerifyAccessToken(tokenStr)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			errorResponse(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}

		sub, _ := claims["sub"].(string)
		if sub == "" {
			errorResponse(w, http.StatusUnauthorized, "invalid_token", "Missing sub claim")
			return
		}

		user, err := getUserProfile(db, sub)
		if err != nil {
			errorResponse(w, http.StatusNotFound, "invalid_token", "User not found")
			return
		}

		resp := map[string]interface{}{
			"sub": sub,
		}
		if user.DisplayName != "" {
			resp["name"] = user.DisplayName
		}
		if user.Email != "" {
			resp["email"] = user.Email
			resp["email_verified"] = true
		}
		if user.AvatarURL != "" {
			resp["picture"] = user.AvatarURL
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// --- Helpers ---

type userProfile struct {
	UserID      string
	DisplayName string
	Email       string
	AvatarURL   string
}

func getUserProfile(db *store.DB, userID string) (*userProfile, error) {
	u := &userProfile{UserID: userID}
	err := db.QueryRow(
		"SELECT display_name, email, avatar_url FROM users WHERE user_id = ?",
		userID,
	).Scan(&u.DisplayName, &u.Email, &u.AvatarURL)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func verifyPKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func errorResponse(w http.ResponseWriter, status int, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}
