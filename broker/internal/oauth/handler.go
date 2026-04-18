// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package oauth provides a server-side token exchange proxy for OAuth providers
// that require a client_secret (e.g. GitHub Apps, LinkedIn). The wallet sends
// the authorization code and PKCE verifier; this handler injects the secret
// and forwards the request to the provider's token endpoint.
package oauth

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ProviderSecret holds the token endpoint and client secret for one provider.
type ProviderSecret struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
}

// Config for the OAuth proxy.
type Config struct {
	// Providers keyed by provider name (e.g. "github", "linkedin").
	Providers map[string]ProviderSecret
}

// Handler serves POST /oauth/token requests from the wallet.
type Handler struct {
	providers map[string]ProviderSecret
	client    *http.Client
}

// New creates an OAuth proxy handler.
func New(cfg Config) *Handler {
	return &Handler{
		providers: cfg.Providers,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

var originPattern = regexp.MustCompile(`^https?://(localhost(:\d+)?|(.+\.)?privasys\.(org|id))$`)

func allowedOrigin(origin string) bool {
	return origin == "" || originPattern.MatchString(origin)
}

// tokenRequest is the JSON body the wallet sends.
type tokenRequest struct {
	Provider     string `json:"provider"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

// HandleToken proxies an OAuth token exchange, injecting the client_secret.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	// CORS
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !allowedOrigin(origin) {
			http.Error(w, `{"error":"origin not allowed"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Parse request
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req tokenRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Provider == "" || req.Code == "" || req.RedirectURI == "" {
		http.Error(w, `{"error":"provider, code, and redirect_uri are required"}`, http.StatusBadRequest)
		return
	}

	ps, ok := h.providers[req.Provider]
	if !ok {
		http.Error(w, `{"error":"unknown provider"}`, http.StatusBadRequest)
		return
	}

	// Build the upstream token request
	form := url.Values{
		"client_id":     {ps.ClientID},
		"client_secret": {ps.ClientSecret},
		"code":          {req.Code},
		"redirect_uri":  {req.RedirectURI},
		"grant_type":    {"authorization_code"},
	}
	if req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}

	upstream, err := http.NewRequest("POST", ps.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("[oauth] failed to build upstream request for %s: %v", req.Provider, err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	upstream.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	upstream.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(upstream)
	if err != nil {
		log.Printf("[oauth] upstream request to %s failed: %v", req.Provider, err)
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Forward the response as-is
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		http.Error(w, `{"error":"failed to read upstream response"}`, http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}
