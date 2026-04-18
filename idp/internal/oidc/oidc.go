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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
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
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "name", "given_name", "family_name", "email", "email_verified",
			"picture", "locale", "phone_number",
			"attestation_level", "auth_time", "iss", "aud", "exp", "iat",
			"roles",
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

	// Transient profile attributes — sourced from social IdP or wallet relay,
	// carried in-memory through the auth code, embedded in the JWT, then GC'd.
	// Never persisted to any database. Keyed by OIDC claim name (e.g. "email", "name").
	Attributes map[string]string
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

// UpdateAttributes patches the attributes on an existing authorization code.
// Used when the wallet relay delivers attributes after FIDO2 already created
// the code (the FIDO2 handler creates the code without attributes; the relay
// delivers them asynchronously via /session/complete).
func (cs *CodeStore) UpdateAttributes(code string, attrs map[string]string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	ac, ok := cs.codes[code]
	if !ok {
		return
	}
	if ac.Attributes == nil {
		ac.Attributes = make(map[string]string)
	}
	for k, v := range attrs {
		ac.Attributes[k] = v
	}
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
// Creates a session with a QR payload for the Privasys Wallet app and returns
// the session data as JSON for the SDK iframe to consume.
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
		prompt := q.Get("prompt")

		// Handle prompt=none (silent auth not supported — always requires wallet interaction).
		if prompt == "none" {
			if redirectURI != "" {
				sep := "?"
				if strings.Contains(redirectURI, "?") {
					sep = "&"
				}
				errURL := redirectURI + sep + "error=login_required"
				if state != "" {
					errURL += "&state=" + url.QueryEscape(state)
				}
				http.Redirect(w, r, errURL, http.StatusFound)
				return
			}
			errorResponse(w, http.StatusBadRequest, "login_required",
				"Silent authentication is not supported — wallet interaction required")
			return
		}

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

		// Validate redirect_uri when provided.
		if redirectURI != "" && !client.ValidRedirectURI(redirectURI) {
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

		// Build QR payload for wallet universal link.
		qrPayload := map[string]interface{}{
			"origin":    "privasys.id",
			"sessionId": sessionID,
			"rpId":      "privasys.id",
			"appName":   "Privasys",
			"brokerUrl": "wss://relay.privasys.org/relay",
		}

		// Tell the wallet which attributes the relying party needs,
		// derived from the requested OIDC scope.
		var requestedAttributes []string
		if strings.Contains(scope, "openid") {
			requestedAttributes = append(requestedAttributes, "sub")
		}
		if strings.Contains(scope, "email") {
			requestedAttributes = append(requestedAttributes, "email")
		}
		if strings.Contains(scope, "profile") {
			requestedAttributes = append(requestedAttributes, "name")
		}
		if strings.Contains(scope, "phone") {
			requestedAttributes = append(requestedAttributes, "phone_number")
		}
		if len(requestedAttributes) > 0 {
			qrPayload["requestedAttributes"] = requestedAttributes
		}

		qrJSON, _ := json.Marshal(qrPayload)
		b64 := base64.RawURLEncoding.EncodeToString(qrJSON)
		universalLink := fmt.Sprintf("https://privasys.id/scp?p=%s", b64)

		// Return session data for the SDK (iframe OIDC flow).
		resp := map[string]interface{}{
			"session_id": sessionID,
			"qr_payload": universalLink,
			"poll_url":   issuerURL + "/session/status?session_id=" + sessionID,
			"expires_in": 300,
		}
		if len(requestedAttributes) > 0 {
			resp["requested_attributes"] = requestedAttributes
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
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
			callbackURL := session.RedirectURI +
				"?code=" + url.QueryEscape(session.AuthCode)
			if session.State != "" {
				callbackURL += "&state=" + url.QueryEscape(session.State)
			}
			resp["redirect_uri"] = callbackURL
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// --- /session/complete ---

// HandleSessionComplete marks an OIDC session as authenticated and returns
// an authorization code. Called by the frame-host (same origin) after the
// wallet completes authentication through the relay, or after social IdP
// callback. This bridges relay/social auth into the OIDC code flow.
func HandleSessionComplete(codes *CodeStore, sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SessionID  string            `json:"session_id"`
			UserID     string            `json:"user_id"`
			Attributes map[string]string `json:"attributes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
			return
		}

		if req.SessionID == "" {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "session_id required")
			return
		}

		session, ok := sessions.Get(req.SessionID)
		if !ok {
			errorResponse(w, http.StatusNotFound, "invalid_request", "Session not found or expired")
			return
		}

		if session.Authenticated {
			// Already completed (FIDO2 handler got there first). Patch in
			// the wallet-relayed attributes before returning the code — the
			// FIDO2 handler creates the code without attributes.
			if len(req.Attributes) > 0 {
				codes.UpdateAttributes(session.AuthCode, req.Attributes)
				log.Printf("session/complete: patched attributes on code for session %s", req.SessionID)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"code": session.AuthCode})
			return
		}

		userID := req.UserID
		if userID == "" {
			userID = "wallet:" + req.SessionID
		}

		authCode := codes.Create(&AuthCode{
			ClientID:            session.ClientID,
			RedirectURI:         session.RedirectURI,
			UserID:              userID,
			Scope:               session.Scope,
			Nonce:               session.Nonce,
			CodeChallenge:       session.CodeChallenge,
			CodeChallengeMethod: session.CodeChallengeMethod,
			AuthTime:            time.Now(),
			Attributes:          req.Attributes,
		})
		sessions.Complete(req.SessionID, userID, authCode)

		log.Printf("session/complete: session %s authenticated (user %s)", req.SessionID, userID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"code": authCode})
	}
}

// --- /token ---

// HandleToken handles the OIDC token exchange (authorization code → tokens,
// refresh_token → tokens, jwt-bearer → tokens).
func HandleToken(reg *clients.Registry, codes *CodeStore, issuer *tokens.Issuer, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "Cannot parse form")
			return
		}

		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			handleAuthorizationCodeGrant(w, r, reg, codes, issuer, db)
		case "refresh_token":
			handleRefreshTokenGrant(w, r, reg, issuer, db)
		case "urn:ietf:params:oauth:grant-type:jwt-bearer":
			handleJWTBearerGrant(w, r, issuer, db)
		default:
			errorResponse(w, http.StatusBadRequest, "unsupported_grant_type",
				"Supported: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:jwt-bearer")
		}
	}
}

const refreshTokenTTL = 30 * 24 * time.Hour // 30 days

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request,
	reg *clients.Registry, codes *CodeStore, issuer *tokens.Issuer, db *store.DB) {

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Support client_secret_basic (HTTP Basic Auth) as fallback.
	if clientID == "" {
		if id, secret, ok := r.BasicAuth(); ok {
			clientID = id
			clientSecret = secret
		}
	}

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

	// Validate redirect_uri matches (skip for JSON-mode sessions with no redirect_uri).
	if ac.RedirectURI != "" && ac.RedirectURI != redirectURI {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Verify PKCE code_verifier.
	if !verifyPKCE(ac.CodeChallenge, codeVerifier) {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// Resolve profile attributes. Prefer transient data from the auth code
	// (social IdP or wallet relay). Fall back to the DB only for legacy
	// passkey users who have profile data stored from prior Auth.js sessions.
	attrs := ac.Attributes
	if attrs == nil {
		attrs = make(map[string]string)
	}
	avatarURL := ""
	if attrs["email"] == "" && attrs["name"] == "" {
		if user, err := getUserProfile(db, ac.UserID); err == nil {
			if user.Email != "" {
				attrs["email"] = user.Email
			}
			if user.DisplayName != "" {
				attrs["name"] = user.DisplayName
			}
			avatarURL = user.AvatarURL
		}
	}

	// Filter attributes to only those allowed by the requested scope.
	filteredAttrs := filterAttributesByScope(attrs, ac.Scope)

	// Get user roles.
	roles, _ := db.GetRoles(ac.UserID)

	// Issue ID token.
	idToken, err := issuer.IssueIDToken(tokens.IDTokenClaims{
		Subject:          ac.UserID,
		Email:            filteredAttrs["email"],
		Name:             filteredAttrs["name"],
		Picture:          avatarURL,
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

	// Issue access token (with roles and profile).
	// Access token aud = "privasys-platform" (the resource server trust domain).
	// ID token aud = client_id (per OIDC spec: ID tokens are for the client).
	accessToken, err := issuer.IssueAccessToken(ac.UserID, "privasys-platform", roles, filteredAttrs)
	if err != nil {
		log.Printf("token: access token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	resp := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   900,
		"id_token":     idToken,
		"scope":        ac.Scope,
	}

	// Issue refresh token if offline_access was requested.
	if strings.Contains(ac.Scope, "offline_access") {
		refreshToken, err := issueRefreshToken(db, ac.UserID, ac.ClientID, ac.Scope)
		if err != nil {
			log.Printf("token: refresh token issuance failed: %v", err)
		} else {
			resp["refresh_token"] = refreshToken
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request,
	reg *clients.Registry, issuer *tokens.Issuer, db *store.DB) {

	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Support client_secret_basic (HTTP Basic Auth) as fallback.
	if clientID == "" {
		if id, secret, ok := r.BasicAuth(); ok {
			clientID = id
			clientSecret = secret
		}
	}

	if refreshToken == "" {
		errorResponse(w, http.StatusBadRequest, "invalid_request", "refresh_token required")
		return
	}

	// Validate client.
	ok, err := reg.VerifySecret(clientID, clientSecret)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client")
		return
	}
	if !ok {
		errorResponse(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// Consume the refresh token (rotation: old token is invalidated).
	tokenHash := hashRefreshToken(refreshToken)
	userID, storedClientID, scope, err := db.ConsumeRefreshToken(tokenHash)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return
	}

	// Ensure the client_id matches.
	if storedClientID != clientID {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	// Look up user profile (best-effort for refresh — transient data expired).
	var email, name, avatarURL string
	if user, err := getUserProfile(db, userID); err == nil {
		email = user.Email
		name = user.DisplayName
		avatarURL = user.AvatarURL
	}

	// Build attributes from DB profile and filter by scope.
	refreshAttrs := make(map[string]string)
	if email != "" {
		refreshAttrs["email"] = email
	}
	if name != "" {
		refreshAttrs["name"] = name
	}
	filteredRefreshAttrs := filterAttributesByScope(refreshAttrs, scope)

	// Get current roles.
	roles, _ := db.GetRoles(userID)

	// Issue new access token (with current roles and available profile).
	accessToken, err := issuer.IssueAccessToken(userID, "privasys-platform", roles, filteredRefreshAttrs)
	if err != nil {
		log.Printf("refresh: access token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	// Issue new ID token.
	idToken, err := issuer.IssueIDToken(tokens.IDTokenClaims{
		Subject:          userID,
		Email:            filteredRefreshAttrs["email"],
		Name:             filteredRefreshAttrs["name"],
		Picture:          avatarURL,
		AttestationLevel: "verified",
		Audience:         clientID,
		AuthTime:         time.Now(),
	})
	if err != nil {
		log.Printf("refresh: ID token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	// Issue new refresh token (rotation).
	newRefreshToken, err := issueRefreshToken(db, userID, clientID, scope)
	if err != nil {
		log.Printf("refresh: new refresh token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	resp := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    900,
		"id_token":      idToken,
		"refresh_token": newRefreshToken,
		"scope":         scope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

func handleJWTBearerGrant(w http.ResponseWriter, r *http.Request,
	issuer *tokens.Issuer, db *store.DB) {

	assertion := r.FormValue("assertion")
	scope := r.FormValue("scope")

	if assertion == "" {
		errorResponse(w, http.StatusBadRequest, "invalid_request", "assertion required")
		return
	}

	// Decode assertion header to get kid, then decode claims to get iss/sub.
	parts := strings.SplitN(assertion, ".", 3)
	if len(parts) != 3 {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "Malformed JWT assertion")
		return
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "Cannot decode assertion claims")
		return
	}
	var assertionClaims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &assertionClaims); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "Cannot parse assertion claims")
		return
	}

	// The subject of the assertion is the service account ID.
	accountID, _ := assertionClaims["sub"].(string)
	if accountID == "" {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "Assertion missing sub claim")
		return
	}

	// Look up the service account's public key.
	publicKeyPEM, _, err := db.GetServiceAccount(accountID)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "Unknown service account")
		return
	}

	// Verify the JWT assertion.
	_, err = tokens.VerifyServiceAccountJWT(assertion, publicKeyPEM, issuer.IssuerURL())
	if err != nil {
		log.Printf("jwt-bearer: verification failed for %s: %v", accountID, err)
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "JWT assertion verification failed")
		return
	}

	// Get service account roles.
	roles, _ := db.GetRoles(accountID)

	// Determine audience from scope (e.g. "audience:management-service").
	// Default to "privasys-platform" if no explicit audience scope is provided.
	audience := "privasys-platform"
	for _, s := range strings.Fields(scope) {
		if strings.HasPrefix(s, "audience:") {
			audience = strings.TrimPrefix(s, "audience:")
			break
		}
	}

	// Issue access token (service accounts have no profile attributes).
	accessToken, err := issuer.IssueAccessToken(accountID, audience, roles, nil)
	if err != nil {
		log.Printf("jwt-bearer: access token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	resp := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   900,
		"scope":        scope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// issueRefreshToken generates a random refresh token, stores its hash, and returns the plaintext.
func issueRefreshToken(db *store.DB, userID, clientID, scope string) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	tokenHash := hashRefreshToken(token)

	err := db.StoreRefreshToken(tokenHash, userID, clientID, scope, time.Now().Add(refreshTokenTTL))
	if err != nil {
		return "", err
	}
	return token, nil
}

func hashRefreshToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
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

		// Include roles.
		roles, _ := db.GetRoles(sub)
		if len(roles) > 0 {
			resp["roles"] = roles
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

// filterAttributesByScope returns only the attributes allowed by the OIDC scope.
// Attribute names follow OIDC Standard Claims (RFC 7519 §5.1):
//   - "email" scope → "email"
//   - "profile" scope → "name", "given_name", "family_name", "nickname", "picture", "locale"
//   - "phone" scope → "phone_number"
//
// Unknown attributes pass through only if their key matches a scope token
// (future extensibility).
func filterAttributesByScope(attrs map[string]string, scope string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string)
	hasEmail := strings.Contains(scope, "email")
	hasProfile := strings.Contains(scope, "profile")
	hasPhone := strings.Contains(scope, "phone")
	for k, v := range attrs {
		switch k {
		case "email":
			if hasEmail || hasProfile {
				out[k] = v
			}
		case "name", "family_name", "given_name", "nickname", "picture", "locale":
			if hasProfile {
				out[k] = v
			}
		case "phone_number":
			if hasPhone {
				out[k] = v
			}
		default:
			// Extensible: allow attribute if its key appears as a scope token.
			if strings.Contains(scope, k) {
				out[k] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
