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
	"slices"
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

// presenceMarketplaceKey is how the registry spells the ceremony (seeded by
// management-service migration 056). It is hard-coded here, and only here,
// because presenceAttribute is deliberately absent from the referential that
// would otherwise carry the binding: a reservation still has to name the
// registry's exact spelling or the whole authorization fails as unknown.
const presenceMarketplaceKey = "privasys:" + presenceAttribute

func acrRequested(acrValues, v string) bool {
	for _, s := range strings.Fields(acrValues) {
		if s == v {
			return true
		}
	}
	return false
}

// validateACRValues rejects unknown acr_values entries (hard error — never a
// silent downgrade). Returns the trimmed value. Shared by /authorize and
// /device_authorization.
func validateACRValues(raw string) (string, error) {
	acrValues := strings.TrimSpace(raw)
	for _, v := range strings.Fields(acrValues) {
		if !acrSupported(v) {
			return "", fmt.Errorf("unsupported acr_values entry: %s", v)
		}
	}
	return acrValues, nil
}

// applyPresenceACR: gov-presence asks for a live holder-presence ceremony.
// Add the ceremonial holder_present attribute (essential, gov) — per-request,
// never scope-derived, and deliberately not subject to the client whitelist:
// it discloses no personal data, only "the document holder is present now".
// It IS a priced gov attribute, so the voucher mint reserves credits for it
// like any other. Shared by /authorize and /device_authorization.
func applyPresenceACR(acrValues string, requested []string,
	reqs map[string]AttributeRequirement) ([]string, map[string]AttributeRequirement) {
	if !acrRequested(acrValues, "gov-presence") {
		return requested, reqs
	}
	present := false
	for _, k := range requested {
		if k == presenceAttribute {
			present = true
		}
	}
	if !present {
		requested = append(requested, presenceAttribute)
	}
	if reqs == nil {
		reqs = map[string]AttributeRequirement{}
	}
	reqs[presenceAttribute] = AttributeRequirement{Essential: true, Assurance: "gov"}
	return requested, reqs
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

// decodeDisclosure reads a disclosure token's `value` and whether it is a
// charged FAILURE receipt (v0.6.0+: a signed token with a `failure` block that
// the ceremony emits — and charges for — when a well-formed request did not
// pass). Decodes the JWS payload WITHOUT verifying the signature: the acr
// claim is only a hint; the relying party re-verifies the VC itself, so a
// forged value at worst mislabels the caller's own token.
func decodeDisclosure(v string) (value interface{}, isFailure bool, ok bool) {
	if !looksLikeDisclosureToken(v) {
		return nil, false, false
	}
	parts := strings.SplitN(strings.TrimSuffix(v, "~"), ".", 3)
	if len(parts) < 2 {
		return nil, false, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false, false
	}
	var p struct {
		Value   interface{}     `json:"value"`
		Failure json.RawMessage `json:"failure"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, false, false
	}
	return p.Value, len(p.Failure) > 0, true
}

// successfulGovDisclosure reports a disclosure that certified a fact (true OR
// false) and is NOT a charged failure receipt — e.g. age_over_18:false for a
// genuine under-18 holder counts, but a "commitment did not open" failure
// receipt does not.
func successfulGovDisclosure(v string) bool {
	_, isFailure, ok := decodeDisclosure(v)
	return ok && !isFailure
}

// presenceAffirmed reports that a holder_present disclosure certified presence
// (value:true). A failure receipt (value:false) means the live check did not
// pass, so presence was NOT established regardless of the token being validly
// signed.
func presenceAffirmed(v string) bool {
	value, isFailure, ok := decodeDisclosure(v)
	if !ok || isFailure {
		return false
	}
	b, _ := value.(bool)
	return b
}

// acrForCode computes the ACHIEVED authentication context class for a
// completed ceremony, strongest first: "gov-presence" when a live
// holder_present disclosure arrived (and no gov attribute arrived raw),
// "gov-fresh" when at least one gov-assured attribute arrived as a
// disclosure token and none arrived raw, otherwise "wallet". Computed from
// what actually happened, never from what was requested.
func acrForCode(ac *AuthCode, client *clients.Client) string {
	reqs := attributeRequirements(ac.Scope, ac.NamedAttributes, client)
	govToken, govRaw := false, false
	for key, req := range reqs {
		if req.Assurance != "gov" {
			continue
		}
		if v, ok := ac.Attributes[key]; ok && v != "" {
			if looksLikeDisclosureToken(v) {
				// A charged failure receipt is signed but did not certify the
				// fact — it must not lift the assurance tier.
				if successfulGovDisclosure(v) {
					govToken = true
				}
			} else {
				govRaw = true
			}
		}
	}
	// Ceremonial: per-request (gov-presence), never scope-derived, so it is
	// not in reqs. gov-presence only when the live check AFFIRMED presence
	// (value:true) — a failure receipt (value:false) is charged but does not
	// establish presence.
	if presenceAffirmed(ac.Attributes[presenceAttribute]) && !govRaw {
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
		"claims_supported":                      claimsSupported(),
		// The per-attribute request path. A scope is a coarse bundle and cannot
		// name a government-backed `_id` key at all, so advertise both the
		// parameter and where to read the key list from — an integrator that
		// discovers only `scopes_supported` would conclude the platform sells
		// nothing it cannot spell as a scope.
		"privasys_attributes_parameter_supported": true,
		"privasys_attributes_referential":         issuerURL + "/referential/canonical-attributes.json",
	}

	body, _ := json.MarshalIndent(doc, "", "  ")

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(body)
	}
}

// claimsSupported is every canonical attribute key plus the protocol claims the
// IdP adds itself. Built from the referential rather than restated: the
// hand-written list this replaces had gone stale by ten identity attributes, and
// a discovery document that under-reports what the IdP issues is how an
// integrator concludes an attribute does not exist.
func claimsSupported() []string {
	out := []string{"sub"}
	for _, a := range attributes.All {
		out = append(out, a.Key)
	}
	// email_verified rides alongside email rather than being an attribute of its
	// own; the rest are protocol, not profile.
	return append(out, "email_verified", "acr", "attestation_level", "auth_time",
		"iss", "aud", "exp", "iat", "roles", "wallet")
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

	// NamedAttributes carries the canonical keys the relying party asked for by
	// name (the `attributes` parameter). It has to survive onto the code because
	// the token endpoint filters what the wallet returned, and a request-only key
	// is invisible to a scope: without this a disclosure the client paid for
	// would be dropped one step before the ID token.
	NamedAttributes []string

	// Transient profile attributes — sourced from social IdP or wallet relay,
	// carried in-memory through the auth code, embedded in the JWT, then GC'd.
	// Never persisted to any database. Keyed by OIDC claim name (e.g. "email", "name").
	Attributes map[string]string

	// SessionRelay carries per-request browser→enclave session metadata
	// captured by the wallet during a `mode:"session-relay"` flow. Forwarded
	// verbatim into the issued ID token under the `session` and `att_*`
	// top-level claims by the token endpoint, then GC'd. Optional.
	SessionRelay map[string]interface{}

	// WalletVerified is set true only when the pending session this code was
	// minted from was WALLET-ASSERTED: an enrolled, attested wallet instance
	// proved possession of its WIA-bound holder key over the session id
	// (POST /session/assert-wallet). It drives a non-identifying `wallet`
	// class marker on the access token so an attested app runtime can
	// recognise a wallet caller for a `free_for:["wallet"]` API-fee
	// exemption (x-privasys.price) WITHOUT learning or linking the pairwise
	// identity. A constant shared by all wallet users, it carries no
	// per-user data. Social logins, browser passkeys and forged
	// /session/complete calls never set it — WebAuthn alone is not a wallet.
	WalletVerified bool
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

// MarkWalletVerified patches the wallet-class marker onto an existing
// authorization code. Used when the wallet's assert (see
// SessionStore.MarkWalletAsserted) arrives after the code was already
// minted. A consumed or expired code is silently ignored: the token was (or
// will be) issued without the class, which only costs the caller the fee
// exemption, never grants it.
func (cs *CodeStore) MarkWalletVerified(code string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if ac, ok := cs.codes[code]; ok {
		ac.WalletVerified = true
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

	// NamedAttributes from the /authorize `attributes` parameter (canonical keys
	// only, unknown ones already dropped). Threaded onto the auth code.
	NamedAttributes []string

	// RequestedKeys is the effective requested attribute set /authorize
	// resolved for this session (scope-derived + named, whitelist-capped,
	// presence applied). A pushed step-up approval commits to the hash of
	// exactly this set, and its completion re-derives the hash from here —
	// an approval can never authorise a different request than the one the
	// holder saw.
	RequestedKeys []string

	// Set when the wallet completes FIDO2 authentication.
	Authenticated bool
	UserID        string
	AuthCode      string // The authorization code to deliver to the browser.

	// WalletAsserted is set by POST /session/assert-wallet after an enrolled
	// wallet instance proved possession of its WIA-bound holder key over this
	// session id. It is the ONLY source of the auth code's WalletVerified
	// class marker: WebAuthn alone never grants it (a browser passkey is not
	// a wallet), and nothing client-declared on /session/complete can mint
	// it. WalletAssertedKey is a non-identifying thumbprint of the asserting
	// instance's holder key, for audit logs only.
	WalletAsserted    bool
	WalletAssertedKey string
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

// MarkWalletAsserted marks a pending session wallet-asserted (see
// AuthSession.WalletAsserted). When the session has already completed, the
// existing auth code is returned so the caller can patch the class onto it
// (the assert lost the race with completion); otherwise completedCode is
// empty and the code minted later inherits the flag. ok is false for an
// unknown or expired session.
func (ss *SessionStore) MarkWalletAsserted(sessionID, instanceKey string) (completedCode string, ok bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, found := ss.sessions[sessionID]
	if !found || time.Now().After(s.ExpiresAt) {
		return "", false
	}
	s.WalletAsserted = true
	s.WalletAssertedKey = instanceKey
	if s.Authenticated {
		return s.AuthCode, true
	}
	return "", true
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

// CompleteIfPending marks the session authenticated only when no other path
// completed it first. A pushed step-up approval uses this instead of
// Complete so it can never override a ceremony that won the race — the
// approval is then simply reported as lost.
func (ss *SessionStore) CompleteIfPending(sessionID, userID, authCode string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.sessions[sessionID]
	if !ok || s.Authenticated || time.Now().After(s.ExpiresAt) {
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

// AttributeStepUp wires the push arm of attribute step-up into /authorize.
// When a request carries a session_hint identifying a holder whose standing
// grant for this client is NARROWER than the request, the IdP pushes only
// the delta to the holder's wallet for one-tap approval instead of forcing
// a full QR ceremony. Pass nil to disable the arm entirely.
type AttributeStepUp struct {
	// Issuer verifies an OIDC access token presented as session_hint.
	Issuer *tokens.Issuer
	// WalletSession resolves a "wallet:<token>" hint (the wallet's own
	// bearer format). Optional.
	WalletSession func(token string) (string, bool)
	// Sessions is the durable session store carrying each grant's recorded
	// attribute set.
	Sessions *sessions.Store
	// Push records a pending wallet approval bound to `session` and its
	// exact requested set, and delivers the push. `payload` is the same
	// descriptor the QR carries (requested set, requirements, vouchers) so
	// the wallet's consent path is identical to the scan path; `added` is
	// the delta the consent screen shows. Returns false when the holder has
	// no push-capable wallet registered.
	Push func(sub string, session *AuthSession, added []string, payload map[string]interface{}) bool
}

// resolveHint resolves a session_hint to the holder's sub. The hint is a
// CLAIM used only to decide who to push to — it authorises nothing, and a
// hint that fails verification simply disables the push arm for the request.
func (s *AttributeStepUp) resolveHint(hint string) string {
	if s == nil || hint == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(hint, "wallet:"); ok {
		if s.WalletSession == nil {
			return ""
		}
		if sub, valid := s.WalletSession(rest); valid {
			return sub
		}
		return ""
	}
	if s.Issuer == nil {
		return ""
	}
	claims, err := s.Issuer.VerifyAccessToken(hint)
	if err != nil {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return sub
}

// subtractKeys returns the members of a that are not in b, preserving order.
func subtractKeys(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, k := range b {
		have[k] = true
	}
	var out []string
	for _, k := range a {
		if !have[k] {
			out = append(out, k)
		}
	}
	return out
}

// HandleAuthorize handles the OIDC authorization request.
// Creates a session with a QR payload for the Privasys Wallet app and returns
// the session data as JSON for the SDK iframe to consume.
func HandleAuthorize(reg *clients.Registry, sessionStore *SessionStore, issuerURL string, minter *voucher.Minter, stepUp *AttributeStepUp) http.HandlerFunc {
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
		// downgrading an RP that asked for a stronger ceremony is exactly
		// the failure a regulated RP cannot tolerate.
		acrValues, acrErr := validateACRValues(q.Get("acr_values"))
		if acrErr != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_request", acrErr.Error())
			return
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

		// The per-attribute request path. Unlike acr_values this is NOT a hard
		// error on an unknown key: it is the parameter a relying party fills
		// from a referential it fetched itself, so it may legitimately name a
		// key newer than this build.
		namedAttributes := parseAttributesParam(q.Get("attributes"))

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
			NamedAttributes:     namedAttributes,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			CreatedAt:           time.Now(),
			ExpiresAt:           time.Now().Add(5 * time.Minute),
		}
		sessionStore.Create(session)

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

		// Tell the wallet which attributes the relying party needs: the ones its
		// OIDC scope reaches plus the ones it named outright, then filtered by
		// the client's required_attributes whitelist (if set).
		requested := requestedAttributes(scope, namedAttributes, client)
		reqs := attributeRequirements(scope, namedAttributes, client)

		requested, reqs = applyPresenceACR(acrValues, requested, reqs)

		// A pushed step-up approval commits to the hash of exactly this set;
		// its completion re-derives the hash from the session (see
		// AuthSession.RequestedKeys).
		session.RequestedKeys = requested

		if len(requested) > 0 {
			qrPayload["requestedAttributes"] = requested
			qrPayload["attributeRequirements"] = reqs
		}

		// Reserve the relying party's credits for any paid (gov) attributes and
		// carry the resulting disclosure vouchers to the wallet, which relays
		// them to the issuing enclave.
		vouchers, err := mintDisclosureVouchers(r.Context(), minter, client, reqs,
			strings.TrimSpace(r.URL.Query().Get("billing_grant")))
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
		if len(requested) > 0 {
			resp["requested_attributes"] = requested
			resp["attribute_requirements"] = reqs
		}

		// Attribute step-up by push: a session_hint that resolves to a holder
		// whose standing grant for this client is narrower than this request
		// gets the DELTA pushed to their wallet for one-tap approval. The
		// hint only chooses who to push to. The live presence ceremony can
		// never ride a push approval — it needs the wallet's full flow — and
		// with no push-capable wallet the SDK simply runs the ceremony.
		if stepUp != nil && stepUp.Sessions != nil && stepUp.Push != nil {
			if sub := stepUp.resolveHint(q.Get("session_hint")); sub != "" {
				if granted, ok := stepUp.Sessions.GrantedAttributesForApp(sub, clientID); ok {
					added := subtractKeys(requested, granted)
					if len(added) > 0 && !slices.Contains(added, presenceAttribute) {
						pushed := stepUp.Push(sub, session, added, qrPayload)
						resp["step_up"] = map[string]interface{}{
							"pushed": pushed,
							"added":  added,
						}
						log.Printf("authorize: step-up delta %v for client %s (pushed=%v)",
							added, clientID, pushed)
					}
				}
			}
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
			NamedAttributes:     session.NamedAttributes,
			CodeChallenge:       session.CodeChallenge,
			CodeChallengeMethod: session.CodeChallengeMethod,
			AuthTime:            time.Now(),
			Attributes:          req.Attributes,
			// Wallet class only when an enrolled wallet instance asserted
			// this session over /session/assert-wallet (WIA + holder-key
			// PoP). This is the wallet-PUSH completion path, so the flag is
			// what fixes "truest wallet users pay": the wallet asserts
			// during approval and the code minted here inherits it. Social
			// logins and forged /session/complete calls never set it.
			WalletVerified: session.WalletAsserted,
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

	// Filter attributes to only those the relying party asked for.
	filteredAttrs := filterAttributesRequested(attrs, ac.Scope, ac.NamedAttributes)

	// Further restrict to the client's required_attributes whitelist, which is
	// mandatory: a client that names nothing receives nothing, so an old row with
	// an empty whitelist cannot keep collecting the scope-derived set here after
	// /authorize stopped asking the wallet for it.
	//
	// The ceremonial holder_present disclosure is exempt, mirroring the
	// authorize side: it is added per-request by acr_values=gov-presence (not
	// registration-time), discloses no personal data, and IS the receipt the
	// relying party paid the presence ceremony for.
	client, _ := reg.Get(ac.ClientID)
	restricted := make(map[string]string, 1)
	if client != nil {
		for _, key := range client.RequiredAttributes {
			if v, ok := filteredAttrs[key]; ok {
				restricted[key] = v
			}
		}
	}
	if v, ok := filteredAttrs[presenceAttribute]; ok {
		restricted[presenceAttribute] = v
	}
	filteredAttrs = restricted

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

	// Record the attribute set this grant covered, so a later /authorize
	// carrying a session_hint can compute the delta of a widened request
	// (attribute step-up by push). Recorded as the effective REQUESTED set
	// the holder decided on (scope-derived + named, whitelist-capped) — not
	// the values that arrived: an attribute the holder saw and declined, or
	// has no value for, must not re-prompt on every connect.
	if sess != nil && sid != "" {
		granted := requestedAttributes(ac.Scope, ac.NamedAttributes, client)
		if err := sess.SetGrantedAttributes(sid, granted); err != nil {
			log.Printf("token: record granted attributes: %v", err)
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

	// Wallet-class marker (x-privasys.price free_for:["wallet"]): a genuine
	// wallet WebAuthn ceremony stamps a constant, non-identifying `wallet=true`
	// claim so an attested runtime can grant the wallet fee exemption without
	// learning the pairwise identity. Carried on the access token only (it is a
	// resource-server authorisation signal, not an ID-token profile claim).
	if ac.WalletVerified {
		if filteredAttrs == nil {
			filteredAttrs = map[string]string{}
		}
		filteredAttrs["wallet"] = "true"
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
	filteredRefreshAttrs := filterAttributesRequested(nil, scope, nil)

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

// parseAttributesParam reads the per-request `attributes` parameter: the
// per-attribute request path, and the model going forward.
//
// A relying party names canonical keys directly (space- or comma-separated)
// instead of hoping a coarse scope happens to contain what it wants. This is the
// only way to reach a request-only key such as `given_name_id`, and it is
// additive: the scope-derived set a client has always received is unchanged, so
// nothing an already-registered client sees moves.
//
// Unknown keys are dropped rather than rejected. The alternative is a hard error
// on a parameter a relying party may well populate from a newer referential than
// the one this IdP embeds, and a sign-in that fails outright is a worse answer
// than a sign-in missing an attribute the client can see is absent.
func parseAttributesParam(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, k := range strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == ',' || r == '+' }) {
		if !attributes.Keys[k] || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// whitelistedAttributes returns the client's required_attributes as a set.
//
// A client that declares none reaches nothing: the whitelist is the declaration
// that a relying party consumes attributes at all, so its absence is a request
// for none of them rather than permission for every key its scope happens to
// reach. Registration refuses an empty list (see validateRequiredAttributes), so
// this is the runtime half of one rule — it catches a row that predates the rule
// and would otherwise be served the scope-derived set forever.
//
// "sub" is always present: it is OpenID Connect's subject identifier, not an
// attribute the referential prices or the wallet discloses.
func whitelistedAttributes(client *clients.Client) map[string]bool {
	if client == nil {
		return map[string]bool{"sub": true}
	}
	allowed := make(map[string]bool, len(client.RequiredAttributes)+1)
	for _, a := range client.RequiredAttributes {
		allowed[a] = true
	}
	// Always keep "sub" (required by OpenID Connect).
	allowed["sub"] = true
	return allowed
}

// namedByRegistration reports whether a client's required_attributes whitelist
// names a request-only key on this request.
//
// A whitelist is the registration-time half of naming, and without it the
// per-attribute model has no answer for a client that cannot change its request:
// migrating such a client's `birthdate` to `birthdate_id` would otherwise move it
// from a government-verified disclosure to nothing at all, which is a worse
// answer than the downgrade the migration exists to prevent.
//
// The scope still has to admit the key, which is what keeps this strictly weaker
// than the `attributes` parameter. A client that whitelisted a passport key but
// asks for `openid email` is not charged for a disclosure this request cannot
// carry, and a migrated client sees exactly what it saw before: the identity
// scope, the same one disclosure, the same one charge.
func namedByRegistration(attr attributes.Attribute, scope string, allowed map[string]bool) bool {
	return attr.RequestOnly && allowed[attr.Key] &&
		attr.Scope != "" && strings.Contains(scope, attr.Scope)
}

// requestedAttributes derives the attribute keys a relying party needs: the
// scope-derived set, plus the keys it named on the request, then intersected
// with the client's required_attributes whitelist (when set). "sub" is always
// included for an openid request. Shared by /authorize and
// /device_authorization so the wallet sees one consistent list regardless of
// entry point.
//
// The two paths are deliberately not equivalent. A scope is coarse and historic:
// `identity` still yields exactly the identity baseline it always has. A named
// key is precise, and naming is the only way to reach a request-only key — every
// government-backed `_id` attribute is one, so no client is ever charged for a
// passport disclosure it did not spell out. The whitelist still wins over both:
// a registration is a ceiling, not a starting point.
//
// A whitelist entry is one of the two ways of naming (see namedByRegistration).
func requestedAttributes(scope string, named []string, client *clients.Client) []string {
	allowed := whitelistedAttributes(client)

	inRequest := make(map[string]bool, len(named))
	for _, k := range named {
		inRequest[k] = true
	}

	var requested []string
	if strings.Contains(scope, "openid") {
		requested = append(requested, "sub")
	}
	for _, attr := range attributes.All {
		if !attr.InScope(scope) && !inRequest[attr.Key] && !namedByRegistration(attr, scope, allowed) {
			continue
		}
		requested = append(requested, attr.Key)
	}

	filtered := requested[:0]
	for _, a := range requested {
		if allowed[a] {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// AttributeRequirement tells the wallet what a relying party needs for one
// attribute: whether it is essential (must be present to complete sign-in) and
// the assurance level (see the identity-verifier (KYC) design).
type AttributeRequirement struct {
	Essential bool   `json:"essential"`
	Assurance string `json:"assurance"` // "gov" | "any"
}

// attributeRequirements returns per-attribute requirements for the request.
// Essential = the client's required_attributes whitelist, which is the only
// statement of what a relying party needs; a client that declares none requests
// nothing, so there is nothing here to mark essential. Assurance = "gov" for a
// government-backed key (only the identity-verifier enclave can certify one),
// else "any". Additive to the payload: older wallets ignore it.
//
// Assurance is read off the KEY, which is the point of the `_id` convention:
// `given_name` is the holder's own profile value and `given_name_id` is the
// passport one, so there is nothing left for a request to disambiguate and no
// way for a scope to downgrade what a relying party asked for.
func attributeRequirements(scope string, named []string, client *clients.Client) map[string]AttributeRequirement {
	essential := map[string]bool{}
	if client != nil {
		for _, a := range client.RequiredAttributes {
			essential[a] = true
		}
	}

	out := map[string]AttributeRequirement{}
	for _, key := range requestedAttributes(scope, named, client) {
		if key == "sub" {
			continue
		}
		assurance := "any"
		if attr, ok := attributes.ByKey[key]; ok && attr.IsGovVerified() {
			assurance = "gov"
		}
		out[key] = AttributeRequirement{Essential: essential[key], Assurance: assurance}
	}
	return out
}

// reservableMarketplaceKeys picks the namespaced keys a set of requirements
// would reserve credits for, deduplicated and in a stable order.
//
// Everything the referential does not price is dropped — the identity scope also
// carries the raw document fields the verifier reads off the chip, which are
// certified by the same ceremony but have no registry row, and reserving one
// fails the whole authorization as an unknown attribute.
//
// Deduplication is defensive: nothing in the referential maps two canonical keys
// onto one registry row today, and while a pair shares a row in spirit only the
// government-backed half is priced. It stays because the referential is free to
// point two keys at one row and the failure would be a relying party charged
// twice for a single disclosure.
func reservableMarketplaceKeys(reqs map[string]AttributeRequirement) []string {
	seen := map[string]bool{}
	var keys []string
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for key, req := range reqs {
		if req.Assurance != "gov" {
			continue
		}
		if key == presenceAttribute {
			// Ceremonial and deliberately non-canonical, so the referential
			// cannot price it — but migration 056 does seed its registry row,
			// and a gov-presence ceremony that reserved nothing would run the
			// live biometric check for free.
			add(presenceMarketplaceKey)
			continue
		}
		if mk, ok := attributes.MarketplaceKey(key); ok {
			add(mk)
		}
	}
	sort.Strings(keys) // stable request for deterministic grouping/tests
	return keys
}

// disclosureReservationTTL is how long a per-attribute credit hold survives. It
// must outlive first-time capture (a passport read on onboarding), so it is well
// longer than the signed voucher's own lifetime; an unused hold is released on
// expiry.
const disclosureReservationTTL = 30 * time.Minute

// mintDisclosureVouchers reserves the relying party's credits for the
// gov-assurance attributes it is requesting and returns the signed vouchers to
// thread into the wallet payload. It fires only for a billable relying party
// with a configured minter, and only for gov attributes the marketplace actually
// prices; everything else discloses free and returns (nil, nil). A returned
// voucher.ErrInsufficient means the RP cannot pay — the caller answers 402.
func mintDisclosureVouchers(ctx context.Context, m *voucher.Minter, client *clients.Client, reqs map[string]AttributeRequirement, billingGrant string) ([]voucher.MintedVoucher, error) {
	if m == nil || !m.Enabled() || client == nil || !client.BillableRP || client.BillingAccountID == "" {
		return nil, nil
	}
	keys := reservableMarketplaceKeys(reqs)
	if len(keys) == 0 {
		return nil, nil
	}
	rpID := client.RPID
	if rpID == "" {
		rpID = client.ClientID
	}
	return m.Mint(ctx, client.BillingAccountID, rpID, keys, disclosureReservationTTL, billingGrant, client.ClientID)
}

// filterAttributesRequested returns only the attributes the relying party
// actually asked for: those its scope reaches, plus the keys it named on the
// request. Uses the shared canonical attribute definitions.
//
// `named` has to come along or every request-only key would be dropped here
// after the wallet went to the trouble of disclosing it — a `given_name_id` the
// client spelled out is exactly as requested as an `email` its scope implied.
func filterAttributesRequested(attrs map[string]string, scope string, named []string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	inRequest := make(map[string]bool, len(named))
	for _, k := range named {
		inRequest[k] = true
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
			// Known canonical attribute — allowed when its scope was requested
			// or the relying party named it.
			// Special case: email is also allowed under profile scope.
			if attr.InScope(scope) || inRequest[k] || (k == "email" && strings.Contains(scope, "profile")) {
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
