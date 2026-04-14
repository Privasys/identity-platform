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
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
	qrcode "github.com/skip2/go-qrcode"
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
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "name", "email", "email_verified", "picture",
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
// Serves an HTML page that displays a QR code for the Privasys Wallet,
// polls for session completion, and redirects back to the relying party.
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
				http.Redirect(w, r, redirectURI+sep+"error=login_required&state="+url.QueryEscape(state), http.StatusFound)
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
		qrPayload := map[string]string{
			"origin":    "privasys.id",
			"sessionId": sessionID,
			"rpId":      "privasys.id",
			"brokerUrl": "wss://relay.privasys.org/relay",
		}

		qrJSON, _ := json.Marshal(qrPayload)
		// Base64url-encode the QR payload as a universal link for the wallet.
		b64 := base64.RawURLEncoding.EncodeToString(qrJSON)
		universalLink := fmt.Sprintf("https://privasys.id/scp?p=%s", b64)

		// Generate QR code as PNG and embed as data URI.
		qrPNG, err := qrcode.Encode(universalLink, qrcode.Medium, 280)
		if err != nil {
			log.Printf("authorize: QR encode error: %v", err)
			errorResponse(w, http.StatusInternalServerError, "server_error", "Failed to generate QR code")
			return
		}
		qrDataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG)

		data := authPageData{
			SessionID: sessionID,
			QRPayload: universalLink,
			QRDataURI: template.URL(qrDataURI),
			PollURL:   issuerURL + "/session/status?session_id=" + sessionID,
			ExpiresIn: 300,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := authPageTmpl.Execute(w, data); err != nil {
			log.Printf("authorize: template error: %v", err)
		}
	}
}

// authPageData is the template data for the authorization page.
type authPageData struct {
	SessionID string
	QRPayload string       // Universal link URL for the wallet
	QRDataURI template.URL // data:image/png;base64,... (trusted data URI)
	PollURL   string
	ExpiresIn int
}

// authPageTmpl is the HTML page served at /authorize.
// It renders a server-generated QR code, polls for wallet authentication, and redirects on success.
var authPageTmpl = template.Must(template.New("authorize").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in with Privasys ID</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f8f9fa;
    color: #1a1a2e;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: #fff;
    border-radius: 16px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08);
    padding: 48px 40px;
    max-width: 420px;
    width: 100%;
    text-align: center;
  }
  .logo {
    width: 48px;
    height: 48px;
    margin: 0 auto 24px;
  }
  h1 { font-size: 22px; font-weight: 600; margin-bottom: 8px; }
  .subtitle { font-size: 14px; color: #666; margin-bottom: 32px; }
  .qr-frame {
    display: inline-block;
    padding: 16px;
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e8e8e8;
    margin-bottom: 24px;
  }
  .qr-frame img { display: block; width: 280px; height: 280px; }
  .status { font-size: 14px; color: #666; margin-bottom: 8px; }
  .timer { font-size: 13px; color: #999; }
  .status.ok { color: #16a34a; font-weight: 600; }
  .status.err { color: #dc2626; font-weight: 600; }
  .spinner {
    display: none; width: 32px; height: 32px;
    border: 3px solid #e8e8e8; border-top-color: #3b82f6;
    border-radius: 50%; animation: spin .8s linear infinite;
    margin: 16px auto;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .wallet-btn {
    display: none; margin-top: 16px;
  }
  .wallet-btn a {
    display: inline-block; padding: 12px 24px;
    background: #1a1a2e; color: #fff; text-decoration: none;
    border-radius: 8px; font-size: 15px; font-weight: 500;
  }
  @media (max-width: 640px) {
    .wallet-btn { display: block; }
    .qr-frame { display: none; }
  }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <rect width="48" height="48" rx="10" fill="#1a1a2e"/>
      <path d="M12 36L24 12L36 36" stroke="#4ade80" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M18 28L24 16L30 28" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </div>
  <h1>Sign in with Privasys ID</h1>
  <p class="subtitle">Scan the QR code with your Privasys Wallet</p>
  <div class="qr-frame"><img src="{{.QRDataURI}}" alt="QR Code"></div>
  <div class="wallet-btn">
    <a href="{{.QRPayload}}">Open Privasys Wallet</a>
  </div>
  <div class="spinner" id="spinner"></div>
  <p class="status" id="status">Waiting for wallet&hellip;</p>
  <p class="timer" id="timer"></p>
</div>
<script>
(function(){
  var pollURL   = "{{.PollURL}}";
  var remaining = {{.ExpiresIn}};
  var timerEl   = document.getElementById("timer");
  var statusEl  = document.getElementById("status");
  var spinnerEl = document.getElementById("spinner");

  function pad(n){ return n < 10 ? "0"+n : ""+n; }
  function tick(){
    timerEl.textContent = "Expires in " + Math.floor(remaining/60) + ":" + pad(remaining%60);
  }
  tick();

  var countdown = setInterval(function(){
    if(--remaining <= 0){
      clearInterval(countdown); clearInterval(poller);
      statusEl.textContent = "Session expired. Please try again.";
      statusEl.className = "status err";
      timerEl.textContent = "";
    } else { tick(); }
  }, 1000);

  var poller = setInterval(function(){
    fetch(pollURL).then(function(r){ return r.json(); }).then(function(d){
      if(d.authenticated){
        clearInterval(poller); clearInterval(countdown);
        statusEl.textContent = "Authenticated! Redirecting\u2026";
        statusEl.className = "status ok";
        spinnerEl.style.display = "block";
        timerEl.textContent = "";
        window.location.href = d.redirect_uri;
      }
    }).catch(function(){});
  }, 2000);
})();
</script>
</body>
</html>`))

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

	// Get user roles.
	roles, _ := db.GetRoles(ac.UserID)

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

	// Issue access token (with roles).
	accessToken, err := issuer.IssueAccessToken(ac.UserID, ac.ClientID, roles)
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

	// Look up user profile.
	user, err := getUserProfile(db, userID)
	if err != nil {
		log.Printf("refresh: user lookup failed for %s: %v", userID, err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "User lookup failed")
		return
	}

	// Get current roles.
	roles, _ := db.GetRoles(userID)

	// Issue new access token (with current roles).
	accessToken, err := issuer.IssueAccessToken(userID, clientID, roles)
	if err != nil {
		log.Printf("refresh: access token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	// Issue new ID token.
	idToken, err := issuer.IssueIDToken(tokens.IDTokenClaims{
		Subject:          userID,
		Email:            user.Email,
		Name:             user.DisplayName,
		Picture:          user.AvatarURL,
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
		"expires_in":    3600,
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
	audience := ""
	for _, s := range strings.Fields(scope) {
		if strings.HasPrefix(s, "audience:") {
			audience = strings.TrimPrefix(s, "audience:")
			break
		}
	}

	// Issue access token.
	accessToken, err := issuer.IssueAccessToken(accountID, audience, roles)
	if err != nil {
		log.Printf("jwt-bearer: access token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	resp := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
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
