// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package social implements OAuth2/OIDC federation with external identity
// providers (GitHub, Google, Microsoft, LinkedIn). It handles the
// redirect → callback → session-complete flow for social sign-in via
// the Privasys IdP.
package social

import (
	"crypto/rand"
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
	sessionID string // OIDC session_id to complete
	provider  string // Which social provider
	expiresAt time.Time
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

func (ss *stateStore) create(sessionID, provider string) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := hex.EncodeToString(b)

	ss.mu.Lock()
	ss.states[state] = &stateEntry{
		sessionID: sessionID,
		provider:  provider,
		expiresAt: time.Now().Add(10 * time.Minute),
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

// --- Handlers ---

// Handler manages social authentication flows.
type Handler struct {
	providers  *Providers
	states     *stateStore
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

	// Create CSRF state.
	state := h.states.create(sessionID, providerName)

	// Build authorization URL.
	authURL, _ := url.Parse(prov.AuthURL)
	q := authURL.Query()
	q.Set("client_id", prov.ClientID)
	q.Set("redirect_uri", h.issuerURL+"/auth/social/callback")
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(prov.Scopes, " "))
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

	// Exchange code for access token.
	token, err := h.exchangeCode(prov, code)
	if err != nil {
		log.Printf("social/%s: token exchange failed: %v", entry.provider, err)
		h.callbackError(w, "Authentication failed — could not exchange code")
		return
	}

	// Fetch user info.
	userInfo, err := h.fetchUserInfo(prov, token)
	if err != nil {
		log.Printf("social/%s: user info failed: %v", entry.provider, err)
		h.callbackError(w, "Authentication failed — could not fetch user info")
		return
	}

	// Build a stable user_id: "provider:provider_id"
	userID := fmt.Sprintf("%s:%s", entry.provider, userInfo.ID)

	// Complete the OIDC session.
	session, ok := h.sessions.Get(entry.sessionID)
	if !ok {
		h.callbackError(w, "Session expired — please try again")
		return
	}

	if session.Authenticated {
		h.callbackSuccess(w)
		return
	}

	authCode := h.codes.Create(&oidc.AuthCode{
		ClientID:            session.ClientID,
		RedirectURI:         session.RedirectURI,
		UserID:              userID,
		Scope:               session.Scope,
		Nonce:               session.Nonce,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: session.CodeChallengeMethod,
		AuthTime:            time.Now(),
		Attributes:          map[string]string{"email": userInfo.Email, "name": userInfo.Name},
	})
	h.sessions.Complete(entry.sessionID, userID, authCode)

	log.Printf("social/%s: authenticated user %s (session %s)", entry.provider, userID, entry.sessionID)

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

// --- OAuth2 helpers ---

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (h *Handler) exchangeCode(prov *Provider, code string) (string, error) {
	data := url.Values{
		"client_id":     {prov.ClientID},
		"client_secret": {prov.ClientSecret},
		"code":          {code},
		"redirect_uri":  {h.issuerURL + "/auth/social/callback"},
		"grant_type":    {"authorization_code"},
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

// UserInfo contains the minimal user profile from a social provider.
type UserInfo struct {
	ID    string
	Email string
	Name  string
}

func (h *Handler) fetchUserInfo(prov *Provider, accessToken string) (*UserInfo, error) {
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

	// Parse provider-specific user info format.
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse userinfo: %w", err)
	}

	info := &UserInfo{}

	switch prov.Name {
	case "github":
		if v, ok := raw["id"]; ok {
			info.ID = fmt.Sprintf("%v", v)
		}
		if v, ok := raw["email"].(string); ok {
			info.Email = v
		}
		if v, ok := raw["name"].(string); ok {
			info.Name = v
		}
		if v, ok := raw["login"].(string); ok && info.Name == "" {
			info.Name = v
		}
	case "google":
		if v, ok := raw["sub"].(string); ok {
			info.ID = v
		}
		if v, ok := raw["email"].(string); ok {
			info.Email = v
		}
		if v, ok := raw["name"].(string); ok {
			info.Name = v
		}
	case "microsoft":
		if v, ok := raw["id"].(string); ok {
			info.ID = v
		}
		if v, ok := raw["mail"].(string); ok {
			info.Email = v
		}
		if v, ok := raw["displayName"].(string); ok {
			info.Name = v
		}
	case "linkedin":
		if v, ok := raw["sub"].(string); ok {
			info.ID = v
		}
		if v, ok := raw["email"].(string); ok {
			info.Email = v
		}
		if v, ok := raw["name"].(string); ok {
			info.Name = v
		}
	default:
		// Generic: try common field names
		for _, k := range []string{"sub", "id", "user_id"} {
			if v, ok := raw[k]; ok {
				info.ID = fmt.Sprintf("%v", v)
				break
			}
		}
		if v, ok := raw["email"].(string); ok {
			info.Email = v
		}
		if v, ok := raw["name"].(string); ok {
			info.Name = v
		}
	}

	if info.ID == "" {
		return nil, fmt.Errorf("could not extract user ID from provider response")
	}

	return info, nil
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
