// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package social implements OAuth2/OIDC federation with external identity
// providers (GitHub, Google, Microsoft, LinkedIn). It handles the
// redirect → callback → session-complete flow for social sign-in via
// the Privasys IdP.
package social

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/attributes"
	"github.com/Privasys/idp/internal/oidc"
)

// Provider holds the OAuth2 configuration for a single external IdP.
type Provider struct {
	Name         string // e.g. "github"
	DisplayName  string // e.g. "GitHub"
	AuthURL      string // Authorization endpoint
	TokenURL     string // Token endpoint
	UserInfoURL  string // User info endpoint
	ClientID     string
	ClientSecret string
	Scopes       []string
	// PKCE indicates the provider's authorization server supports PKCE (S256),
	// which we then use on the upstream authorization-code leg. Confidential
	// providers that don't support it (e.g. LinkedIn) set PKCE=false and
	// authenticate with the client secret only; sending a code_verifier to such
	// a provider is rejected as invalid_client.
	PKCE bool
}

// Providers maps provider names to their configuration.
type Providers struct {
	mu        sync.RWMutex
	providers map[string]*Provider
}

// NewProviders creates an empty provider registry.
func NewProviders() *Providers {
	return &Providers{providers: make(map[string]*Provider)}
}

// Register adds a provider. Only registers if client ID is non-empty.
func (p *Providers) Register(prov *Provider) {
	if prov.ClientID == "" {
		return
	}
	p.mu.Lock()
	p.providers[prov.Name] = prov
	p.mu.Unlock()
	log.Printf("social: registered provider %s", prov.Name)
}

// Get returns a provider by name.
func (p *Providers) Get(name string) (*Provider, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	prov, ok := p.providers[name]
	return prov, ok
}

// List returns all registered provider names.
func (p *Providers) List() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, 0, len(p.providers))
	for name := range p.providers {
		names = append(names, name)
	}
	return names
}

// --- State store (CSRF protection for OAuth2 callbacks) ---

type stateEntry struct {
	sessionID string // OIDC session_id to complete (web-SDK mode)
	provider  string // Which social provider
	verifier  string // PKCE code_verifier for the upstream token exchange
	expiresAt time.Time

	// Wallet-link mode (sessionID is empty). The wallet links a provider to
	// seed its local profile; there is no OIDC session. After the upstream
	// exchange the callback stashes the normalised attributes under a one-time
	// result code and 302-redirects to the wallet's custom-scheme redirectURI.
	walletMode  bool
	redirectURI string // wallet custom-scheme callback (allowlisted)
	nonce       string // wallet-supplied, echoed back for correlation
	challenge   string // wallet PKCE S256 challenge, verified at /wallet/link/result
}

type stateStore struct {
	mu     sync.Mutex
	states map[string]*stateEntry
}

func newStateStore() *stateStore {
	ss := &stateStore{states: make(map[string]*stateEntry)}
	go func() {
		for {
			time.Sleep(time.Minute)
			ss.cleanup()
		}
	}()
	return ss
}

func (ss *stateStore) create(sessionID, provider, verifier string) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := hex.EncodeToString(b)

	ss.mu.Lock()
	ss.states[state] = &stateEntry{
		sessionID: sessionID,
		provider:  provider,
		verifier:  verifier,
		expiresAt: time.Now().Add(10 * time.Minute),
	}
	ss.mu.Unlock()
	return state
}

func (ss *stateStore) createWallet(provider, verifier, redirectURI, nonce, challenge string) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := hex.EncodeToString(b)

	ss.mu.Lock()
	ss.states[state] = &stateEntry{
		provider:    provider,
		verifier:    verifier,
		expiresAt:   time.Now().Add(10 * time.Minute),
		walletMode:  true,
		redirectURI: redirectURI,
		nonce:       nonce,
		challenge:   challenge,
	}
	ss.mu.Unlock()
	return state
}

func (ss *stateStore) consume(state string) (*stateEntry, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	e, ok := ss.states[state]
	if !ok || time.Now().After(e.expiresAt) {
		delete(ss.states, state)
		return nil, false
	}
	delete(ss.states, state)
	return e, true
}

func (ss *stateStore) cleanup() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	now := time.Now()
	for k, v := range ss.states {
		if now.After(v.expiresAt) {
			delete(ss.states, k)
		}
	}
}

// --- Wallet-link result store (one-time codes) ---

// linkResult holds the normalised attributes from a wallet-link flow, keyed by
// a one-time code. It is retrieved exactly once at /wallet/link/result, after
// the caller proves possession of the PKCE verifier bound at /wallet/link.
type linkResult struct {
	provider  string
	userID    string
	attrs     map[string]string
	verified  map[string]bool
	challenge string // wallet PKCE S256 challenge; verifier checked at retrieval
	expiresAt time.Time
}

type resultStore struct {
	mu      sync.Mutex
	results map[string]*linkResult
}

func newResultStore() *resultStore {
	rs := &resultStore{results: make(map[string]*linkResult)}
	go func() {
		for {
			time.Sleep(time.Minute)
			rs.cleanup()
		}
	}()
	return rs
}

func (rs *resultStore) create(res *linkResult) string {
	b := make([]byte, 32)
	rand.Read(b)
	code := hex.EncodeToString(b)
	res.expiresAt = time.Now().Add(5 * time.Minute)

	rs.mu.Lock()
	rs.results[code] = res
	rs.mu.Unlock()
	return code
}

func (rs *resultStore) consume(code string) (*linkResult, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	res, ok := rs.results[code]
	if !ok || time.Now().After(res.expiresAt) {
		delete(rs.results, code)
		return nil, false
	}
	delete(rs.results, code)
	return res, true
}

func (rs *resultStore) cleanup() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	now := time.Now()
	for k, v := range rs.results {
		if now.After(v.expiresAt) {
			delete(rs.results, k)
		}
	}
}

// --- Handlers ---

// Handler manages social authentication flows.
type Handler struct {
	providers  *Providers
	states     *stateStore
	results    *resultStore
	codes      *oidc.CodeStore
	sessions   *oidc.SessionStore
	issuerURL  string
	httpClient *http.Client
}

// NewHandler creates a social auth handler.
func NewHandler(providers *Providers, codes *oidc.CodeStore, sessions *oidc.SessionStore, issuerURL string) *Handler {
	return &Handler{
		providers:  providers,
		states:     newStateStore(),
		results:    newResultStore(),
		codes:      codes,
		sessions:   sessions,
		issuerURL:  issuerURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// HandleRedirect initiates the OAuth2 flow by redirecting to the provider.
// GET /auth/social?provider=github&session_id=xxx
func (h *Handler) HandleRedirect(w http.ResponseWriter, r *http.Request) {
	providerName := r.URL.Query().Get("provider")
	sessionID := r.URL.Query().Get("session_id")

	if providerName == "" || sessionID == "" {
		http.Error(w, "provider and session_id required", http.StatusBadRequest)
		return
	}

	prov, ok := h.providers.Get(providerName)
	if !ok {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}

	// Verify session exists.
	if _, ok := h.sessions.Get(sessionID); !ok {
		http.Error(w, "session not found or expired", http.StatusBadRequest)
		return
	}

	// Build authorization URL.
	authURL, _ := url.Parse(prov.AuthURL)
	q := authURL.Query()
	q.Set("client_id", prov.ClientID)
	q.Set("redirect_uri", h.issuerURL+"/auth/social/callback")
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(prov.Scopes, " "))

	// PKCE on the upstream leg when the provider supports it. Confidential
	// providers that don't (e.g. LinkedIn) authenticate with the client secret
	// only — sending a code_verifier there is rejected as invalid_client.
	var verifier string
	if prov.PKCE {
		var challenge string
		verifier, challenge = generatePKCE()
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	state := h.states.create(sessionID, providerName, verifier)
	q.Set("state", state)
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// HandleCallback processes the OAuth2 callback from the provider.
// GET /auth/social/callback?code=xxx&state=xxx
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		h.callbackError(w, fmt.Sprintf("Provider error: %s", errParam))
		return
	}

	if code == "" || state == "" {
		h.callbackError(w, "Missing code or state parameter")
		return
	}

	// Validate CSRF state.
	entry, ok := h.states.consume(state)
	if !ok {
		h.callbackError(w, "Invalid or expired state — please try again")
		return
	}

	prov, ok := h.providers.Get(entry.provider)
	if !ok {
		h.callbackError(w, "Unknown provider")
		return
	}

	// Exchange code for access token (PKCE: send the verifier bound to state).
	token, err := h.exchangeCode(prov, code, entry.verifier)
	if err != nil {
		log.Printf("social/%s: token exchange failed: %v", entry.provider, err)
		h.callbackError(w, "Authentication failed — could not exchange code")
		return
	}

	// Fetch raw user info from the provider.
	raw, err := h.fetchRawUserInfo(prov, token)
	if err != nil {
		log.Printf("social/%s: user info failed: %v", entry.provider, err)
		h.callbackError(w, "Authentication failed — could not fetch user info")
		return
	}

	accessToken := token // keep a reference for GitHub email fallback

	// Normalise raw claims using the shared canonical mappings.
	attrs, providerUID := attributes.NormalizeClaims(entry.provider, raw)

	// Build a stable user_id: "provider:provider_id"
	if providerUID == "" {
		log.Printf("social/%s: could not extract user ID from provider response", entry.provider)
		h.callbackError(w, "Authentication failed — could not identify user")
		return
	}
	userID := fmt.Sprintf("%s:%s", entry.provider, providerUID)

	// GitHub may return null for email when the user has a private
	// email. Fall back to the /user/emails endpoint.
	if attrs["email"] == "" && entry.provider == "github" {
		attrs["email"] = h.fetchGitHubPrimaryEmail(accessToken)
	}

	// Wallet-link mode: no OIDC session. Stash the normalised attributes (plus
	// per-attribute verification status) under a one-time result code and
	// 302-redirect back to the wallet's custom-scheme URI. The wallet redeems
	// the code at /wallet/link/result with its PKCE verifier.
	if entry.walletMode {
		res := &linkResult{
			provider:  entry.provider,
			userID:    userID,
			attrs:     attrs,
			verified:  providerVerified(entry.provider, raw),
			challenge: entry.challenge,
		}
		resultCode := h.results.create(res)
		sep := "?"
		if strings.Contains(entry.redirectURI, "?") {
			sep = "&"
		}
		redir := fmt.Sprintf("%s%scode=%s&nonce=%s", entry.redirectURI, sep,
			url.QueryEscape(resultCode), url.QueryEscape(entry.nonce))
		log.Printf("social/%s: wallet link complete (%d attrs), redirecting", entry.provider, len(attrs))
		http.Redirect(w, r, redir, http.StatusFound)
		return
	}

	// Complete the OIDC session.
	session, ok := h.sessions.Get(entry.sessionID)
	if !ok {
		h.callbackError(w, "Session expired — please try again")
		return
	}

	if session.Authenticated {
		// Session already authenticated (e.g. passkey). Patch the social
		// profile attributes onto the existing auth code so the JWT
		// carries verified claims from the social provider.
		if attrs["email"] == "" {
			log.Printf("social/%s: no email returned for session %s — rejecting", entry.provider, entry.sessionID)
			h.callbackError(w, "No verified email found from this provider. Please try a different one.")
			return
		}
		h.codes.UpdateAttributes(session.AuthCode, attrs)
		log.Printf("social/%s: patched %d attributes on existing code for session %s",
			entry.provider, len(attrs), entry.sessionID)
		h.callbackSuccess(w)
		return
	}

	authCode := h.codes.Create(&oidc.AuthCode{
		ClientID:            session.ClientID,
		RedirectURI:         session.RedirectURI,
		UserID:              userID,
		Scope:               session.Scope,
		Nonce:               session.Nonce,
		ACRValues:           session.ACRValues,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: session.CodeChallengeMethod,
		AuthTime:            time.Now(),
		Attributes:          attrs,
	})
	h.sessions.Complete(entry.sessionID, userID, authCode)

	log.Printf("social/%s: authenticated user %s (session %s, %d attrs)", entry.provider, userID, entry.sessionID, len(attrs))

	h.callbackSuccess(w)
}

// HandleProviders returns the list of configured social providers.
// GET /auth/social/providers?session_id=xxx
func (h *Handler) HandleProviders(w http.ResponseWriter, r *http.Request) {
	names := h.providers.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": names,
	})
}

// --- Wallet-link handlers ---

// allowedWalletSchemes is the set of custom URL schemes the wallet may use as
// its link callback (one per build stage, see the auth design "Custom URL Schemes").
// Restricting the redirect prevents an open redirect / token-leak to a
// malicious app.
var allowedWalletSchemes = []string{
	"privasys-wallet://",
	"privasys-wallet-dev://",
	"privasys-wallet-preview://",
}

func allowedWalletRedirect(uri string) bool {
	for _, s := range allowedWalletSchemes {
		if strings.HasPrefix(uri, s) {
			return true
		}
	}
	return false
}

// HandleWalletLink initiates a wallet profile-link flow (no OIDC session). The
// wallet opens this in the system browser; the IdP performs the upstream OAuth
// with its held secret and redirects the result back to the wallet.
// GET /wallet/link?provider=github&redirect_uri=privasys-wallet://link/callback
//
//	&nonce=xxx&code_challenge=yyy&code_challenge_method=S256
func (h *Handler) HandleWalletLink(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	providerName := q.Get("provider")
	redirectURI := q.Get("redirect_uri")
	nonce := q.Get("nonce")
	challenge := q.Get("code_challenge")
	challengeMethod := q.Get("code_challenge_method")

	if providerName == "" || redirectURI == "" || nonce == "" {
		http.Error(w, "provider, redirect_uri and nonce required", http.StatusBadRequest)
		return
	}
	if !allowedWalletRedirect(redirectURI) {
		http.Error(w, "redirect_uri scheme not allowed", http.StatusBadRequest)
		return
	}
	// PKCE is mandatory on the wallet leg too: it binds redemption of the
	// one-time result code to the wallet instance that started the flow, so a
	// hijacked deep link cannot redeem it.
	if challenge == "" {
		http.Error(w, "code_challenge is required (PKCE)", http.StatusBadRequest)
		return
	}
	if challengeMethod != "" && challengeMethod != "S256" {
		http.Error(w, "only S256 code_challenge_method is supported", http.StatusBadRequest)
		return
	}

	prov, ok := h.providers.Get(providerName)
	if !ok {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}
	authURL, _ := url.Parse(prov.AuthURL)
	uq := authURL.Query()
	uq.Set("client_id", prov.ClientID)
	uq.Set("redirect_uri", h.issuerURL+"/auth/social/callback")
	uq.Set("response_type", "code")
	uq.Set("scope", strings.Join(prov.Scopes, " "))

	// Upstream PKCE only when the provider supports it (see HandleRedirect).
	var verifier string
	if prov.PKCE {
		var upstreamChallenge string
		verifier, upstreamChallenge = generatePKCE()
		uq.Set("code_challenge", upstreamChallenge)
		uq.Set("code_challenge_method", "S256")
	}
	state := h.states.createWallet(providerName, verifier, redirectURI, nonce, challenge)
	uq.Set("state", state)
	authURL.RawQuery = uq.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// walletLinkAttr is one normalised attribute returned to the wallet.
type walletLinkAttr struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Verified bool   `json:"verified"`
}

// HandleWalletLinkResult redeems a one-time result code for the normalised
// attributes from a wallet-link flow. The caller must present the PKCE verifier
// matching the challenge bound at /wallet/link.
// GET /wallet/link/result?code=xxx&code_verifier=yyy
func (h *Handler) HandleWalletLinkResult(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	verifier := r.URL.Query().Get("code_verifier")
	if code == "" || verifier == "" {
		http.Error(w, `{"error":"code and code_verifier required"}`, http.StatusBadRequest)
		return
	}

	res, ok := h.results.consume(code)
	if !ok {
		http.Error(w, `{"error":"invalid or expired code"}`, http.StatusBadRequest)
		return
	}
	if !verifyChallenge(res.challenge, verifier) {
		http.Error(w, `{"error":"PKCE verification failed"}`, http.StatusBadRequest)
		return
	}

	attrs := make([]walletLinkAttr, 0, len(res.attrs))
	for k, v := range res.attrs {
		if v == "" {
			continue
		}
		attrs = append(attrs, walletLinkAttr{Key: k, Value: v, Verified: res.verified[k]})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"provider":   res.provider,
		"sub":        res.userID,
		"attributes": attrs,
	})
}

// providerVerified returns, per canonical attribute key, whether the provider's
// raw response marks it verified — mirrors the wallet's isProviderVerified using
// the shared referential's verificationClaims.
func providerVerified(provider string, raw map[string]interface{}) map[string]bool {
	out := map[string]bool{}
	prov, ok := attributes.Providers[provider]
	if !ok {
		return out
	}
	for canonicalKey, claimKey := range prov.VerificationClaims {
		if claimKey == "_always_verified" {
			out[canonicalKey] = true
			continue
		}
		switch v := raw[claimKey].(type) {
		case bool:
			out[canonicalKey] = v
		case string:
			out[canonicalKey] = v == "true"
		}
	}
	return out
}

// verifyChallenge checks a PKCE S256 challenge against its verifier.
func verifyChallenge(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

// --- OAuth2 helpers ---

// generatePKCE returns a fresh PKCE code_verifier and its S256 code_challenge
// (RFC 7636). The verifier is 43 base64url chars (32 random bytes); the
// challenge is base64url(SHA-256(verifier)), unpadded.
func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (h *Handler) exchangeCode(prov *Provider, code, verifier string) (string, error) {
	data := url.Values{
		"client_id":     {prov.ClientID},
		"client_secret": {prov.ClientSecret},
		"code":          {code},
		"redirect_uri":  {h.issuerURL + "/auth/social/callback"},
		"grant_type":    {"authorization_code"},
	}
	// Only PKCE providers get a code_verifier; LinkedIn (confidential, no PKCE)
	// rejects the request as invalid_client when one is present.
	if verifier != "" {
		data.Set("code_verifier", verifier)
	}

	req, _ := http.NewRequest("POST", prov.TokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token response %d: %s", resp.StatusCode, string(body))
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tok.AccessToken == "" {
		// GitHub returns access_token in form-encoded format sometimes
		vals, _ := url.ParseQuery(string(body))
		tok.AccessToken = vals.Get("access_token")
	}

	if tok.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}

	return tok.AccessToken, nil
}

// fetchRawUserInfo calls the provider's UserInfo endpoint and returns the
// raw JSON object. Claim normalisation is handled by attributes.NormalizeClaims.
func (h *Handler) fetchRawUserInfo(prov *Provider, accessToken string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", prov.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo response %d: %s", resp.StatusCode, string(body))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse userinfo: %w", err)
	}
	return raw, nil
}

// fetchGitHubPrimaryEmail calls GET https://api.github.com/user/emails
// and returns the primary verified email address, or "" if none found.
func (h *Handler) fetchGitHubPrimaryEmail(accessToken string) string {
	req, _ := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("social/github: /user/emails request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return ""
	}

	// Return the primary verified email.
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	// Fall back to any verified email.
	for _, e := range emails {
		if e.Verified {
			return e.Email
		}
	}
	return ""
}

// --- Callback HTML ---

func (h *Handler) callbackSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html>
<html><head><title>Privasys Auth</title></head>
<body><script>
if (window.opener) {
  window.opener.postMessage({type:'privasys:social-complete'}, '*');
}
window.close();
</script>
<p>Authentication complete. You can close this window.</p>
</body></html>`))
}

func (h *Handler) callbackError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	safeMsg := strings.ReplaceAll(msg, "'", "\\'")
	safeMsg = strings.ReplaceAll(safeMsg, "<", "&lt;")
	w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Privasys Auth</title></head>
<body><script>
if (window.opener) {
  window.opener.postMessage({type:'privasys:social-error',error:'%s'}, '*');
}
</script>
<p>%s</p>
<p><a href="javascript:window.close()">Close this window</a></p>
</body></html>`, safeMsg, safeMsg)))
}
