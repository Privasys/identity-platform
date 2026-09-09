// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package spend

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Privasys/idp/internal/tokens"
)

// TokenTyp is the JOSE typ of a spend token.
const TokenTyp = "spend+jwt"

// AssertionTyp is the JOSE typ of the client assertion an app signs to
// request a token (private_key_jwt, RFC 7523 profile).
const AssertionTyp = "spend-client+jwt"

// TokenPath is the endpoint an app calls to obtain a spend token.
const TokenPath = "/spend/token"

// Authenticator resolves the user behind a bearer (an access token or a
// wallet session token). Provided by the sessions store.
type Authenticator func(r *http.Request) (userID string, err error)

// AccountEnsurer makes sure the user has a platform account the credit
// service can debit (mgmt EnsureAccount). Optional; nil skips it.
type AccountEnsurer func(ctx context.Context, sub string) error

// Handler serves the consent and token endpoints.
type Handler struct {
	store    *Store
	issuer   *tokens.Issuer
	auth     Authenticator
	keys     *keyCache
	resolver AppResolver
	ensure   AccountEnsurer
	ttl      time.Duration
	now      func() time.Time
}

// Config wires a Handler.
type Config struct {
	Store    *Store
	Issuer   *tokens.Issuer
	Auth     Authenticator
	Resolver AppResolver
	Ensure   AccountEnsurer
	// TokenTTL bounds a spend token's lifetime (default 24h). A token also
	// never outlives the consent session behind it.
	TokenTTL time.Duration
	// HTTP is the client used to fetch app JWKS (tests inject one).
	HTTP *http.Client
}

// New builds a Handler.
func New(c Config) *Handler {
	ttl := c.TokenTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Handler{
		store:    c.Store,
		issuer:   c.Issuer,
		auth:     c.Auth,
		keys:     newKeyCache(c.Resolver, c.HTTP),
		resolver: c.Resolver,
		ensure:   c.Ensure,
		ttl:      ttl,
		now:      time.Now,
	}
}

// --- consents (user-facing) --------------------------------------------

// HandleListConsents serves GET /spend/consents: the user's live spenders.
func (h *Handler) HandleListConsents(w http.ResponseWriter, r *http.Request) {
	userID, err := h.auth(r)
	if err != nil {
		httpUnauth(w, err.Error())
		return
	}
	list, err := h.store.List(userID)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []*Consent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"consents": list})
}

// HandleGetConsent serves GET /spend/consents/{app_id}.
func (h *Handler) HandleGetConsent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.auth(r)
	if err != nil {
		httpUnauth(w, err.Error())
		return
	}
	appID := NormaliseAppID(r.PathValue("app_id"))
	c, err := h.store.Get(userID, appID)
	if errors.Is(err, ErrNotFound) {
		httpErr(w, http.StatusNotFound, "no consent for this app")
		return
	}
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// HandleGrantConsent serves POST /spend/consents:
//
//	{"app_id": "<hex app id | client id>", "cap": <credits/month>,
//	 "app_host": "...", "app_name": "..."}
//
// The wallet calls it at sign-in once the user approved "this app may
// spend"; privasys.id/account calls it from the spenders list. It also
// makes sure the user has a platform account, so a wallet-only user
// becomes billable the moment they consent.
func (h *Handler) HandleGrantConsent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.auth(r)
	if err != nil {
		httpUnauth(w, err.Error())
		return
	}
	var req struct {
		AppID   string `json:"app_id"`
		AppHost string `json:"app_host"`
		AppName string `json:"app_name"`
		Cap     int64  `json:"cap"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	appID := NormaliseAppID(req.AppID)
	if appID == "" {
		httpErr(w, http.StatusBadRequest, "app_id required")
		return
	}
	if req.Cap < 0 {
		httpErr(w, http.StatusBadRequest, "cap must not be negative")
		return
	}
	// Fill the display fields from the platform when the caller did not:
	// the consent row is what the user sees under "Apps that may spend".
	if (req.AppHost == "" || req.AppName == "") && h.resolver != nil {
		if _, name, host, err := h.resolver.JWKSURL(r.Context(), appID); err == nil {
			if req.AppHost == "" {
				req.AppHost = host
			}
			if req.AppName == "" {
				req.AppName = name
			}
		} else if errors.Is(err, ErrUnknownApp) {
			httpErr(w, http.StatusNotFound, "unknown app")
			return
		}
	}
	c, err := h.store.Grant(userID, appID, strings.ToLower(strings.TrimSpace(req.AppHost)),
		strings.TrimSpace(req.AppName), req.Cap)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.ensure != nil {
		if err := h.ensure(r.Context(), userID); err != nil {
			// The consent stands; the account will also be ensured on the
			// user's first visit to privasys.id/account.
			log.Printf("spend: ensure account for consent to %s: %v", appID, err)
		}
	}
	writeJSON(w, http.StatusOK, c)
}

// HandleRevokeConsent serves DELETE /spend/consents/{app_id}.
func (h *Handler) HandleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.auth(r)
	if err != nil {
		httpUnauth(w, err.Error())
		return
	}
	appID := NormaliseAppID(r.PathValue("app_id"))
	err = h.store.Revoke(userID, appID)
	if errors.Is(err, ErrNotFound) {
		httpErr(w, http.StatusNotFound, "no consent for this app")
		return
	}
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "app_id": appID})
}

// --- token (app-facing) ------------------------------------------------

// TokenResponse is the body of a successful POST /spend/token.
type TokenResponse struct {
	SpendToken string `json:"spend_token"`
	TokenType  string `json:"token_type"`
	ExpiresIn  int64  `json:"expires_in"`
	Cap        int64  `json:"cap"`
	SID        string `json:"sid"`
}

// HandleToken serves POST /spend/token.
//
// Body (JSON or form): sub = the user the app acts for; client_assertion =
// a JWT signed by the app's spend key with iss = sub = the app id, aud =
// this endpoint's URL, a short exp and a jti. The key is looked up in the
// app's published JWKS by the assertion's kid; the app's consent from that
// user must be live. The token binds the SAME key in cnf, so only the app
// holding it can produce the per-request proofs a callee demands.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	sub, assertion, err := readTokenRequest(r)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	appID, key, err := h.verifyAssertion(r.Context(), assertion)
	if err != nil {
		oauthErr(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	consent, err := h.store.Get(sub, appID)
	if errors.Is(err, ErrNotFound) {
		oauthErr(w, http.StatusForbidden, "consent_required",
			"the user has not allowed this app to spend their credits, or revoked it")
		return
	}
	if err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	now := h.now()
	exp := now.Add(h.ttl)
	if sess, err := h.store.sessions.Get(consent.SID); err == nil && sess.ExpiresAt.Before(exp) {
		exp = sess.ExpiresAt
	}
	if !exp.After(now) {
		oauthErr(w, http.StatusForbidden, "consent_required", "the consent has expired")
		return
	}
	tok, err := h.issuer.IssueSpendToken(tokens.SpendTokenClaims{
		Subject:  sub,
		AppID:    appID,
		SID:      consent.SID,
		Cap:      consent.Cap,
		Cnf:      key.Cnf(),
		IssuedAt: now,
		Expiry:   exp,
		JTI:      randomID(),
	})
	if err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{
		SpendToken: tok,
		TokenType:  "spend",
		ExpiresIn:  int64(exp.Sub(now).Seconds()),
		Cap:        consent.Cap,
		SID:        consent.SID,
	})
}

func readTokenRequest(r *http.Request) (sub, assertion string, err error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var req struct {
			Sub             string `json:"sub"`
			ClientAssertion string `json:"client_assertion"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			return "", "", errors.New("invalid json")
		}
		sub, assertion = req.Sub, req.ClientAssertion
	} else {
		if err := r.ParseForm(); err != nil {
			return "", "", errors.New("invalid form")
		}
		sub, assertion = r.FormValue("sub"), r.FormValue("client_assertion")
	}
	sub = strings.TrimSpace(sub)
	assertion = strings.TrimSpace(assertion)
	if sub == "" {
		return "", "", errors.New("sub required")
	}
	if assertion == "" {
		return "", "", errors.New("client_assertion required")
	}
	return sub, assertion, nil
}

// verifyAssertion checks the app's private-key JWT and returns the app id
// and the published key that signed it.
func (h *Handler) verifyAssertion(ctx context.Context, assertion string) (string, JWK, error) {
	var key JWK
	var appID string
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithAudience(h.issuer.IssuerURL()+TokenPath),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	tok, err := parser.Parse(assertion, func(t *jwt.Token) (any, error) {
		claims, _ := t.Claims.(jwt.MapClaims)
		iss, _ := claims["iss"].(string)
		sub, _ := claims["sub"].(string)
		appID = NormaliseAppID(iss)
		if appID == "" || NormaliseAppID(sub) != appID {
			return nil, errors.New("assertion iss and sub must both be the app id")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("assertion has no kid")
		}
		k, err := h.keys.Key(ctx, appID, kid)
		if err != nil {
			return nil, err
		}
		key = k
		return k.PublicKey()
	})
	if err != nil {
		return "", JWK{}, fmt.Errorf("client assertion: %w", err)
	}
	claims, _ := tok.Claims.(jwt.MapClaims)
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return "", JWK{}, errors.New("client assertion: exp required")
	}
	if exp.Time.Sub(h.now()) > 10*time.Minute {
		return "", JWK{}, errors.New("client assertion: exp too far ahead (max 10 minutes)")
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		return "", JWK{}, errors.New("client assertion: jti required")
	}
	return appID, key, nil
}

// --- mgmt account ensurer -------------------------------------------------

// MgmtAccountEnsurer returns an AccountEnsurer that calls the
// management-service's internal ensure endpoint with the IdP's mgmt token.
// Empty URL or token yields nil (disabled).
func MgmtAccountEnsurer(mgmtURL, token string, client *http.Client) AccountEnsurer {
	if mgmtURL == "" || token == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	base := strings.TrimRight(mgmtURL, "/")
	return func(ctx context.Context, sub string) error {
		body, _ := json.Marshal(map[string]string{"sub": sub})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			base+"/api/v1/internal/accounts/ensure", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("ensure account: status %d", resp.StatusCode)
		}
		return nil
	}
}

// --- helpers ----------------------------------------------------------------

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("spend: rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func httpUnauth(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	httpErr(w, http.StatusUnauthorized, msg)
}

func oauthErr(w http.ResponseWriter, code int, errCode, desc string) {
	writeJSON(w, code, map[string]string{"error": errCode, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
