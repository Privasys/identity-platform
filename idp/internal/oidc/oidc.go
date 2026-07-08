// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package oidc implements the OIDC authorization server endpoints.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/attributes"
	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/sessions"
	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
	"github.com/Privasys/idp/internal/voucher"
)

const (
	// longLivedAudience is the token audience that is issued long-lived.
	// Tokens for it authorise nothing but attestation-server quote
	// verification (POST /verify), so a long lifetime is low-risk — the
	// vault constellation holds one as a static bearer instead of
	// refreshing every 15 minutes. Powerful audiences stay short-lived.
	longLivedAudience = "attestation-server"
	// longLivedTokenTTLSeconds is ~5 years.
	longLivedTokenTTLSeconds = 5 * 365 * 24 * 3600
)

// Authentication context classes (assurance tiers) an RP may request via
// acr_values and that the issued ID token echoes back as `acr`:
//
//	wallet    — interactive device-bound ceremony (wallet push/QR or
//	            passkey). Every authorization here is at least this;
//	            prompt=none is refused.
//	gov-fresh — this ceremony minted at least one gov-assured attribute
//	            as an enclave-signed disclosure token (and none arrived
//	            raw). The RP gets a fresh receipt, not a cached claim.
//	gov-presence — this ceremony additionally proved LIVE HOLDER PRESENCE:
//	            a fresh selfie matched in-enclave against the government
//	            document's portrait (holder_present disclosure). Device
//	            biometrics prove "someone enrolled on this phone"; this
//	            proves the document holder is in front of the camera.
var acrValuesSupported = []string{"wallet", "gov-fresh", "gov-presence"}

// presenceAttribute is the ceremonial marketplace attribute gov-presence
// adds to a request. Deliberately NOT in the canonical referential (it is
// no profile value, and canonical membership would pull it into every
// identity-scope request); the wallet runs a live selfie ceremony for it.
const presenceAttribute = "holder_present"

func acrRequested(acrValues, v string) bool {
	for _, s := range strings.Fields(acrValues) {
		if s == v {
			return true
		}
	}
	return false
}

func acrSupported(v string) bool {
	for _, s := range acrValuesSupported {
		if v == s {
			return true
		}
	}
	return false
}

// looksLikeDisclosureToken reports whether an attribute value is an
// enclave-signed SD-JWT VC disclosure (compact JWS + '~') rather than a
// raw value relayed from the wallet profile.
func looksLikeDisclosureToken(v string) bool {
	return strings.HasPrefix(v, "eyJ") && strings.HasSuffix(v, "~") &&
		strings.Count(v, ".") >= 2
}

// acrForCode computes the ACHIEVED authentication context class for a
// completed ceremony, strongest first: "gov-presence" when a live
// holder_present disclosure arrived (and no gov attribute arrived raw),
// "gov-fresh" when at least one gov-assured attribute arrived as a
// disclosure token and none arrived raw, otherwise "wallet". Computed from
// what actually happened, never from what was requested.
func acrForCode(ac *AuthCode, client *clients.Client) string {
	reqs := attributeRequirementsForScope(ac.Scope, client)
	govToken, govRaw := false, false
	for key, req := range reqs {
		if req.Assurance != "gov" {
			continue
		}
		if v, ok := ac.Attributes[key]; ok && v != "" {
			if looksLikeDisclosureToken(v) {
				govToken = true
			} else {
				govRaw = true
			}
		}
	}
	// Ceremonial: per-request (gov-presence), never scope-derived, so it is
	// not in reqs. Only a genuine disclosure token counts as presence.
	presence := looksLikeDisclosureToken(ac.Attributes[presenceAttribute])
	if presence && !govRaw {
		return "gov-presence"
	}
	if govToken && !govRaw {
		return "gov-fresh"
	}
	return "wallet"
}

// HandleDiscovery returns the OIDC discovery document.
func HandleDiscovery(issuerURL string) http.HandlerFunc {
	doc := map[string]interface{}{
		"issuer":                                issuerURL,
		"authorization_endpoint":                issuerURL + "/authorize",
		"token_endpoint":                        issuerURL + "/token",
		"device_authorization_endpoint":         issuerURL + "/device_authorization",
		"userinfo_endpoint":                     issuerURL + "/userinfo",
		"jwks_uri":                              issuerURL + "/jwks",
		"registration_endpoint":                 issuerURL + "/clients",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:device_code"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "phone", "identity", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256"},
		"acr_values_supported":                  acrValuesSupported,
		"claims_supported": []string{
			"sub", "name", "given_name", "family_name", "email", "email_verified",
			"picture", "locale", "phone_number", "acr",
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

	// ACRValues carries the relying party's requested authentication
	// context classes ("wallet", "gov-fresh") from /authorize. The
	// ACHIEVED class is computed at token issuance from what actually
	// arrived on this code (see acrForCode) — a request is intent, not
	// a promise.
	ACRValues string

	// Transient profile attributes — sourced from social IdP or wallet relay,
	// carried in-memory through the auth code, embedded in the JWT, then GC'd.
	// Never persisted to any database. Keyed by OIDC claim name (e.g. "email", "name").
	Attributes map[string]string

	// SessionRelay carries per-request browser→enclave session metadata
	// captured by the wallet during a `mode:"session-relay"` flow. Forwarded
	// verbatim into the issued ID token under the `session` and `att_*`
	// top-level claims by the token endpoint, then GC'd. Optional.
	SessionRelay map[string]interface{}
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

	// ACRValues from the /authorize request (space-separated, validated
	// against acrValuesSupported). Threaded onto the auth code.
	ACRValues string

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
func HandleAuthorize(reg *clients.Registry, sessions *SessionStore, issuerURL string, minter *voucher.Minter) http.HandlerFunc {
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

		// Validate acr_values (assurance tiers). Unknown values are a hard
		// error rather than the spec's "ignore voluntary claims" — silently
		// downgrading an RP that asked for a stronger ceremony (e.g. a
		// future gov-presence) is exactly the failure a regulated RP cannot
		// tolerate.
		acrValues := strings.TrimSpace(q.Get("acr_values"))
		for _, v := range strings.Fields(acrValues) {
			if !acrSupported(v) {
				errorResponse(w, http.StatusBadRequest, "invalid_request",
					"unsupported acr_values entry: "+v)
				return
			}
		}

		// max_age: accepted for OIDC compliance. Every authorization here is
		// an interactive wallet/passkey ceremony (prompt=none is refused), so
		// auth_time is always fresh and no re-auth forcing is needed; the RP
		// enforces its policy against the auth_time claim in the ID token.
		if ma := q.Get("max_age"); ma != "" {
			if _, err := strconv.Atoi(ma); err != nil {
				errorResponse(w, http.StatusBadRequest, "invalid_request",
					"max_age must be an integer")
				return
			}
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
			ACRValues:           acrValues,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			CreatedAt:           time.Now(),
			ExpiresAt:           time.Now().Add(5 * time.Minute),
		}
		sessions.Create(session)

		// Build QR payload for wallet universal link. clientId identifies the
		// relying party stably (rpId is the shared FIDO2 RP, privasys.id, for
		// every brokered client) — the wallet keys per-app consent on it.
		qrPayload := map[string]interface{}{
			"origin":    "privasys.id",
			"sessionId": sessionID,
			"rpId":      "privasys.id",
			"clientId":  clientID,
			"appName":   "Privasys",
			"brokerUrl": "wss://relay.privasys.org/relay",
		}

		// Tell the wallet which attributes the relying party needs,
		// derived from the requested OIDC scope, then filtered by the
		// client's required_attributes whitelist (if set).
		requestedAttributes := requestedAttributesForScope(scope, client)
		attributeRequirements := attributeRequirementsForScope(scope, client)

		// gov-presence: the RP asked for a live holder-presence ceremony.
		// Add the ceremonial holder_present attribute (essential, gov) —
		// per-request, never scope-derived, and deliberately not subject to
		// the client whitelist: it discloses no personal data, only "the
		// document holder is present now". It IS a priced gov attribute, so
		// the voucher mint below reserves credits for it like any other.
		if acrRequested(acrValues, "gov-presence") {
			present := false
			for _, k := range requestedAttributes {
				if k == presenceAttribute {
					present = true
				}
			}
			if !present {
				requestedAttributes = append(requestedAttributes, presenceAttribute)
			}
			if attributeRequirements == nil {
				attributeRequirements = map[string]AttributeRequirement{}
			}
			attributeRequirements[presenceAttribute] = AttributeRequirement{
				Essential: true, Assurance: "gov",
			}
		}

		if len(requestedAttributes) > 0 {
			qrPayload["requestedAttributes"] = requestedAttributes
			qrPayload["attributeRequirements"] = attributeRequirements
		}

		// Reserve the relying party's credits for any paid (gov) attributes and
		// carry the resulting disclosure vouchers to the wallet, which relays
		// them to the issuing enclave.
		vouchers, err := mintDisclosureVouchers(r.Context(), minter, client, attributeRequirements)
		if err == voucher.ErrInsufficient {
			errorResponse(w, http.StatusPaymentRequired, "insufficient_credits",
				"The relying party has insufficient credits for the requested attributes")
			return
		} else if err != nil {
			log.Printf("authorize: mint disclosure vouchers: %v", err)
			errorResponse(w, http.StatusBadGateway, "voucher_error",
				"Could not reserve attribute credits")
			return
		}
		if len(vouchers) > 0 {
			qrPayload["disclosureVouchers"] = vouchers
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
			resp["attribute_requirements"] = attributeRequirements
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

		// SECURITY: do not mint a synthetic "wallet:<sessionID>" subject when
		// the caller didn't supply a real user_id. The previous behaviour
		// allowed the wallet/relay path to silently produce JWTs with a
		// brand-new sub that had no roles and no profile attributes — users
		// would re-authenticate after a session drop and lose their admin
		// role and email/name.
		// The OIDC session MUST be marked authenticated by the FIDO2 handler
		// (which knows the real user_id) before frame-host calls this
		// endpoint. If we get here with an unauthenticated session and no
		// user_id, the wallet/FIDO2→OIDC linking is broken and we should
		// surface that as a hard auth failure rather than corrupt the token.
		if req.UserID == "" {
			log.Printf("session/complete: refusing to complete session %s without user_id (FIDO2/OIDC linking missing)", req.SessionID)
			errorResponse(w, http.StatusBadRequest, "invalid_request",
				"session not authenticated and no user_id supplied")
			return
		}
		userID := req.UserID

		authCode := codes.Create(&AuthCode{
			ClientID:            session.ClientID,
			RedirectURI:         session.RedirectURI,
			UserID:              userID,
			Scope:               session.Scope,
			Nonce:               session.Nonce,
			ACRValues:           session.ACRValues,
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
//
// `sess` is optional; when nil the unified session model is bypassed
// and tokens are minted without a `sid` claim (legacy behaviour). All
// production wiring should pass a non-nil store.
func HandleToken(reg *clients.Registry, codes *CodeStore, devices *DeviceStore, authSessions *SessionStore, issuer *tokens.Issuer, db *store.DB, sess *sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "Cannot parse form")
			return
		}

		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			handleAuthorizationCodeGrant(w, r, reg, codes, issuer, db, sess)
		case "refresh_token":
			handleRefreshTokenGrant(w, r, reg, issuer, db, sess)
		case "urn:ietf:params:oauth:grant-type:jwt-bearer":
			handleJWTBearerGrant(w, r, issuer, db)
		case "urn:ietf:params:oauth:grant-type:device_code":
			handleDeviceCodeGrant(w, r, reg, codes, devices, authSessions, issuer, db, sess)
		default:
			errorResponse(w, http.StatusBadRequest, "unsupported_grant_type",
				"Supported: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:jwt-bearer, urn:ietf:params:oauth:grant-type:device_code")
		}
	}
}

// handleDeviceCodeGrant implements the RFC 8628 token poll. The client polls
// with its device_code (+ PKCE code_verifier) until the user approves on the
// wallet (or verification page). Until then it returns authorization_pending;
// it returns slow_down when polled too fast, access_denied if the user
// rejected, and expired_token once the device_code lapses.
func handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request,
	reg *clients.Registry, codes *CodeStore, devices *DeviceStore, authSessions *SessionStore,
	issuer *tokens.Issuer, db *store.DB, sess *sessions.Store) {

	deviceCode := r.FormValue("device_code")
	codeVerifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" {
		if id, secret, ok := r.BasicAuth(); ok {
			clientID = id
			clientSecret = secret
		}
	}

	if deviceCode == "" {
		errorResponse(w, http.StatusBadRequest, "invalid_request", "device_code required")
		return
	}

	// Validate the client (public clients have no secret).
	ok, err := reg.VerifySecret(clientID, clientSecret)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client")
		return
	}
	if !ok {
		errorResponse(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// expired_token once the device_code lapses (or was already consumed).
	da, found := devices.GetByDeviceCode(deviceCode)
	if !found {
		errorResponse(w, http.StatusBadRequest, "expired_token", "device_code expired or unknown")
		return
	}
	if da.ClientID != clientID {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	// Rate-limit polling per RFC 8628 §3.5.
	if da.touchPoll() {
		errorResponse(w, http.StatusBadRequest, "slow_down", "Polling too frequently")
		return
	}

	da.mu.Lock()
	denied := da.denied
	da.mu.Unlock()
	if denied {
		devices.Delete(deviceCode)
		errorResponse(w, http.StatusBadRequest, "access_denied", "User denied the request")
		return
	}

	// Approval is signalled by the wallet (or verification page) completing
	// the linked AuthSession via the shared FIDO2/relay path.
	session, sok := authSessions.Get(da.SessionID)
	if !sok || !session.Authenticated {
		errorResponse(w, http.StatusBadRequest, "authorization_pending", "Waiting for user approval")
		return
	}

	// Consume the authorization code the FIDO2 handler created on completion.
	ac, cok := codes.Consume(session.AuthCode)
	if !cok {
		errorResponse(w, http.StatusBadRequest, "expired_token", "Authorization expired before token retrieval")
		return
	}
	if ac.ClientID != clientID {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if !verifyPKCE(ac.CodeChallenge, codeVerifier) {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// Single-use: drop the device authorization now that it is redeemed.
	devices.Delete(deviceCode)

	issueTokensForCode(w, ac, reg, issuer, db, sess)
}

const refreshTokenTTL = 30 * 24 * time.Hour // 30 days

func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request,
	reg *clients.Registry, codes *CodeStore, issuer *tokens.Issuer, db *store.DB, sess *sessions.Store) {

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

	issueTokensForCode(w, ac, reg, issuer, db, sess)
}

// issueTokensForCode mints the ID/access/refresh tokens for a consumed,
// client-validated, PKCE-verified authorization code. Shared by the
// authorization_code and device_code grants so both produce identical tokens
// (roles, sid, audience, attribute handling). The caller must have already
// consumed `ac` from the code store and verified the client and PKCE.
func issueTokensForCode(w http.ResponseWriter, ac *AuthCode,
	reg *clients.Registry, issuer *tokens.Issuer, db *store.DB, sess *sessions.Store) {

	// Resolve profile attributes from transient auth code data
	// (wallet relay or social IdP). No profile data is stored server-side.
	attrs := ac.Attributes
	if attrs == nil {
		attrs = make(map[string]string)
	}

	// Filter attributes to only those allowed by the requested scope.
	filteredAttrs := filterAttributesByScope(attrs, ac.Scope)

	// Further restrict to the client's required_attributes whitelist (if set).
	client, _ := reg.Get(ac.ClientID)
	if client != nil && len(client.RequiredAttributes) > 0 {
		restricted := make(map[string]string, len(client.RequiredAttributes))
		for _, key := range client.RequiredAttributes {
			if v, ok := filteredAttrs[key]; ok {
				restricted[key] = v
			}
		}
		filteredAttrs = restricted
	}

	// Get user roles, filtered to the requested audience namespace.
	// The access token audience is the resource-server trust domain
	// (privasys-platform by default). Only roles in that namespace are
	// emitted — enforces the strict role taxonomy.
	allRoles, _ := db.GetRoles(ac.UserID)
	audience := audienceFromScope(ac.Scope, "privasys-platform")
	roles := filterRolesByAudience(allRoles, audience)

	// Issue ID token.
	// Reuse (or mint) the unified session row for (user, client, device)
	// and embed its sid in the issued tokens. The wallet uses sid as the
	// revocation handle (see internal/sessions).
	//
	// This MUST be FindOrCreateForApp — not an unconditional Create — so
	// the sid in the JWT matches the row the wallet's EncAuth voucher is
	// stored on (`POST /sessions/encauth` resolves the same (user,
	// client, device) tuple). With a per-sign-in sid the SDK's
	// `GET /sessions/{sid}/encauth` would always 404 and silent rebind
	// would never engage. Browser flows carry no stable device id, so
	// device_id is "" on both paths.
	var sid string
	if sess != nil {
		row, err := sess.FindOrCreateForApp(ac.UserID, ac.ClientID, "", refreshTokenTTL)
		if err != nil {
			log.Printf("token: session row lookup/creation failed: %v", err)
		} else {
			sid = row.SID
		}
	}

	idToken, err := issuer.IssueIDToken(tokens.IDTokenClaims{
		Subject:          ac.UserID,
		Email:            filteredAttrs["email"],
		Name:             filteredAttrs["name"],
		Picture:          "",
		AttestationLevel: "verified",
		Audience:         ac.ClientID,
		Nonce:            ac.Nonce,
		AuthTime:         ac.AuthTime,
		ACR:              acrForCode(ac, client),
		SID:              sid,
		SessionRelay:     ac.SessionRelay,
	})
	if err != nil {
		log.Printf("token: ID token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	// Issue access token (with roles and profile).
	// Access token aud is the resource-server trust domain, selected from
	// the scope (audience:<X>, defaulting to privasys-platform).
	// ID token aud = client_id (per OIDC spec: ID tokens are for the client).
	accessToken, err := issuer.IssueAccessTokenWithSID(ac.UserID, audience, sid, roles, filteredAttrs)
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
		refreshToken, err := issueRefreshToken(db, ac.UserID, ac.ClientID, ac.Scope, sid)
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
	reg *clients.Registry, issuer *tokens.Issuer, db *store.DB, sess *sessions.Store) {

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
	userID, storedClientID, scope, sid, err := db.ConsumeRefreshTokenWithSID(tokenHash)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return
	}

	// Ensure the client_id matches.
	if storedClientID != clientID {
		errorResponse(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	// Reject refreshes for revoked sessions. Legacy tokens (sid == "")
	// pre-date the unified session model and are accepted unconditionally.
	if sess != nil && sid != "" {
		if !sess.IsActive(sid) {
			errorResponse(w, http.StatusBadRequest, "invalid_grant", "Session revoked")
			return
		}
		_ = sess.Touch(sid, refreshTokenTTL)
	}

	// No user profile is stored server-side — refresh tokens only carry roles.
	filteredRefreshAttrs := filterAttributesByScope(nil, scope)

	// RFC 6749 §6: clients MAY request a narrower scope on refresh. We
	// support this so the chat UI can mint a per-call token bound to a
	// different audience (e.g. `attestation-server`) without rotating
	// the user's primary session.
	//
	// Rules:
	//   - The optional `scope` form param replaces the access-token scope
	//     for THIS response only. The new refresh token stores the
	//     ORIGINAL scope, so the next refresh starts from the same
	//     baseline.
	//   - Every non-`audience:*` token in the requested scope MUST be
	//     present in the originally granted scope (subset rule). We do
	//     not enforce this for `audience:*` because role filtering by
	//     audience namespace already prevents cross-audience role leakage:
	//     a user without an `<aud>:*` role gets an empty roles claim.
	//   - The audience is derived from the requested scope when present,
	//     otherwise from the stored scope.
	effectiveScope := scope
	if requested := strings.TrimSpace(r.FormValue("scope")); requested != "" {
		stored := map[string]bool{}
		for _, s := range strings.Fields(scope) {
			stored[s] = true
		}
		for _, s := range strings.Fields(requested) {
			if strings.HasPrefix(s, "audience:") {
				continue
			}
			if !stored[s] {
				errorResponse(w, http.StatusBadRequest, "invalid_scope",
					"requested scope "+s+" not present in granted scope")
				return
			}
		}
		effectiveScope = requested
	}

	// Get current roles, filtered to the audience namespace carried by the
	// effective scope (= requested scope if any, else stored).
	allRoles, _ := db.GetRoles(userID)
	audience := audienceFromScope(effectiveScope, "privasys-platform")
	roles := filterRolesByAudience(allRoles, audience)

	// Issue new access token (with current roles and available profile).
	accessToken, err := issuer.IssueAccessTokenWithSID(userID, audience, sid, roles, filteredRefreshAttrs)
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
		Picture:          "",
		AttestationLevel: "verified",
		Audience:         clientID,
		AuthTime:         time.Now(),
		SID:              sid,
	})
	if err != nil {
		log.Printf("refresh: ID token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	// Issue new refresh token (rotation).
	newRefreshToken, err := issueRefreshToken(db, userID, clientID, scope, sid)
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
		"scope":         effectiveScope,
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

	// Determine audience from scope (e.g. "audience:management-service").
	// Default to "privasys-platform" if no explicit audience scope is provided.
	audience := audienceFromScope(scope, "privasys-platform")

	// Get service account roles, filtered to the audience namespace so
	// tokens minted for one trust domain never leak grants for another.
	allRoles, _ := db.GetRoles(accountID)
	roles := filterRolesByAudience(allRoles, audience)

	// Tokens for the attestation-server audience authorise nothing but
	// quote verification (POST /verify), so they may be long-lived — the
	// vault constellation holds one as a static AS bearer instead of
	// refreshing every 15 minutes. Gating on audience (not the service
	// account) means the same SA still gets short-lived tokens for every
	// powerful audience; only this harmless one is long.
	ttlSeconds := 900
	if audience == longLivedAudience {
		ttlSeconds = longLivedTokenTTLSeconds
	}

	// Issue access token (service accounts have no profile attributes).
	accessToken, err := issuer.IssueAccessTokenWithTTL(accountID, audience, "", roles, nil, time.Duration(ttlSeconds)*time.Second)
	if err != nil {
		log.Printf("jwt-bearer: access token issuance failed: %v", err)
		errorResponse(w, http.StatusInternalServerError, "server_error", "Token issuance failed")
		return
	}

	resp := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   ttlSeconds,
		"scope":        scope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// issueRefreshToken generates a random refresh token, stores its hash, and returns the plaintext.
func issueRefreshToken(db *store.DB, userID, clientID, scope, sid string) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	tokenHash := hashRefreshToken(token)

	err := db.StoreRefreshTokenWithSID(tokenHash, userID, clientID, scope, sid, time.Now().Add(refreshTokenTTL))
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

		// Verify the user exists (no profile data stored — just user_id).
		var exists int
		if err := db.QueryRow("SELECT 1 FROM users WHERE user_id = ?", sub).Scan(&exists); err != nil {
			errorResponse(w, http.StatusNotFound, "invalid_token", "User not found")
			return
		}

		resp := map[string]interface{}{
			"sub": sub,
		}

		// Echo back profile claims from the access token.
		// The IdP doesn't store profile data — but the access token carries
		// transient attributes (email, name, etc.) that the wallet relayed
		// during authentication. Return them so relying parties and the
		// management-service can discover them via standard OIDC userinfo.
		for _, attr := range attributes.All {
			if v, ok := claims[attr.Key].(string); ok && v != "" {
				resp[attr.Key] = v
			}
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

func verifyPKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// audienceFromScope extracts the explicit `audience:<X>` token from an OIDC
// scope string, falling back to the supplied default when no audience scope
// is present. The returned audience is also used as the role-namespace prefix
// by filterRolesByAudience — this is the mechanism enforcing the strict role
// taxonomy (e.g. `privasys-platform:admin` only surfaces to consumers of the
// `privasys-platform` audience).
func audienceFromScope(scope, fallback string) string {
	for _, s := range strings.Fields(scope) {
		if strings.HasPrefix(s, "audience:") {
			if aud := strings.TrimPrefix(s, "audience:"); aud != "" {
				return aud
			}
		}
	}
	return fallback
}

// filterRolesByAudience returns only roles whose name is prefixed with
// `<audience>:`. This is how audience-scoped tokens are prevented from
// leaking role grants that belong to a different trust domain. Bare roles
// (no `:` prefix) and roles from other namespaces are dropped.
func filterRolesByAudience(roles []string, audience string) []string {
	if audience == "" || len(roles) == 0 {
		return roles
	}
	prefix := audience + ":"
	out := roles[:0:0]
	for _, r := range roles {
		if strings.HasPrefix(r, prefix) {
			out = append(out, r)
		}
	}
	return out
}

// requestedAttributesForScope derives the attribute keys a relying party needs
// from the requested OIDC scope, then intersects with the client's
// required_attributes whitelist (when set). "sub" is always included for an
// openid request. Shared by /authorize and /device_authorization so the wallet
// sees one consistent list regardless of entry point.
func requestedAttributesForScope(scope string, client *clients.Client) []string {
	var requested []string
	if strings.Contains(scope, "openid") {
		requested = append(requested, "sub")
	}
	for _, attr := range attributes.All {
		if strings.Contains(scope, attr.Scope) {
			requested = append(requested, attr.Key)
		}
	}

	if client != nil && len(client.RequiredAttributes) > 0 {
		allowed := make(map[string]bool, len(client.RequiredAttributes))
		for _, a := range client.RequiredAttributes {
			allowed[a] = true
		}
		// Always keep "sub" (required by OpenID Connect).
		allowed["sub"] = true
		filtered := requested[:0]
		for _, a := range requested {
			if allowed[a] {
				filtered = append(filtered, a)
			}
		}
		requested = filtered
	}
	return requested
}

// AttributeRequirement tells the wallet what a relying party needs for one
// attribute: whether it is essential (must be present to complete sign-in) and
// the assurance level (see the identity-verifier (KYC) design).
type AttributeRequirement struct {
	Essential bool   `json:"essential"`
	Assurance string `json:"assurance"` // "gov" | "any"
}

// attributeRequirementsForScope returns per-attribute requirements for the
// requested scope. Essential = the client's required_attributes whitelist, or
// the email+name identity baseline when the client declares none (so the wallet
// has a consistent essential set without its own heuristic). Assurance = "gov"
// for identity-scoped attributes (only the identity-verifier enclave can certify
// them), else "any". Additive to the payload: older wallets ignore it.
func attributeRequirementsForScope(scope string, client *clients.Client) map[string]AttributeRequirement {
	essential := map[string]bool{}
	if client != nil && len(client.RequiredAttributes) > 0 {
		for _, a := range client.RequiredAttributes {
			essential[a] = true
		}
	} else {
		essential["email"] = true
		essential["name"] = true
	}

	out := map[string]AttributeRequirement{}
	for _, key := range requestedAttributesForScope(scope, client) {
		if key == "sub" {
			continue
		}
		assurance := "any"
		if attr, ok := attributes.ByKey[key]; ok && attr.Scope == "identity" {
			assurance = "gov"
		}
		out[key] = AttributeRequirement{Essential: essential[key], Assurance: assurance}
	}
	return out
}

// disclosureReservationTTL is how long a per-attribute credit hold survives. It
// must outlive first-time capture (a passport read on onboarding), so it is well
// longer than the signed voucher's own lifetime; an unused hold is released on
// expiry.
const disclosureReservationTTL = 30 * time.Minute

// mintDisclosureVouchers reserves the relying party's credits for the
// gov-assurance attributes it is requesting and returns the signed vouchers to
// thread into the wallet payload. It fires only for a billable relying party
// with a configured minter, and only for gov attributes (today reachable solely
// through the Privasys identity-verifier, hence the `privasys:` marketplace
// namespace); everything else discloses free and returns (nil, nil). A returned
// voucher.ErrInsufficient means the RP cannot pay — the caller answers 402.
func mintDisclosureVouchers(ctx context.Context, m *voucher.Minter, client *clients.Client, reqs map[string]AttributeRequirement) ([]voucher.MintedVoucher, error) {
	if m == nil || !m.Enabled() || client == nil || !client.BillableRP || client.BillingAccountID == "" {
		return nil, nil
	}
	var keys []string
	for key, req := range reqs {
		if req.Assurance == "gov" {
			keys = append(keys, "privasys:"+key)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	sort.Strings(keys) // stable request for deterministic grouping/tests
	rpID := client.RPID
	if rpID == "" {
		rpID = client.ClientID
	}
	return m.Mint(ctx, client.BillingAccountID, rpID, keys, disclosureReservationTTL)
}

// filterAttributesByScope returns only the attributes allowed by the OIDC scope,
// using the shared canonical attribute definitions.
func filterAttributesByScope(attrs map[string]string, scope string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range attrs {
		if k == presenceAttribute {
			// Ceremonial (gov-presence): not canonical, allowed under the
			// identity scope — and only ever as an enclave-signed disclosure
			// token, never a raw value.
			if strings.Contains(scope, "identity") && looksLikeDisclosureToken(v) {
				out[k] = v
			}
			continue
		}
		if attr, ok := attributes.ByKey[k]; ok {
			// Known canonical attribute — check if its scope is requested.
			// Special case: email is also allowed under profile scope.
			if strings.Contains(scope, attr.Scope) || (k == "email" && strings.Contains(scope, "profile")) {
				out[k] = v
			}
		} else {
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
