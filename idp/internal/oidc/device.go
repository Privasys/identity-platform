// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Device Authorization Grant (RFC 8628).
//
// This is the auth backbone for input-constrained and browserless clients:
// the Privasys CLI and AI agents. A `POST /device_authorization` mints a
// device_code (polled by the client) plus a user_code + verification_uri
// (surfaced to a human) and a wallet QR payload (scanned for the default,
// attestation-verified path). Approval reuses the exact wallet-relay
// machinery the browser SDK uses: the device request creates an AuthSession,
// the wallet completes it through the FIDO2 endpoints, and the device_code
// token grant (in oidc.go) consumes the resulting authorization code.
//
// Three front-ends on one mechanism:
//   - Wallet QR in the terminal (default): CLI renders qr_payload; wallet
//     scans, verifies attestation, FIDO2-signs; CLI polls /token.
//   - Agent brokers a human login: agent surfaces verification_uri +
//     user_code (or the QR) to its user, then polls /token.
//   - No wallet: human opens verification_uri and completes a passkey/social
//     sign-in there (verification page is separate front-end work).
package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/attributes"
	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/tokens"
	"github.com/Privasys/idp/internal/voucher"
)

const (
	// deviceCodeTTL is how long a device_code / user_code remains valid.
	deviceCodeTTL = 10 * time.Minute
	// defaultDeviceInterval is the minimum seconds between client polls.
	defaultDeviceInterval = 5
	// userCodeAlphabet excludes vowels (no accidental words) and ambiguous
	// glyphs (0/O, 1/I) so a human can read and type the code reliably.
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ23456789"
	// userCodeLen is the number of significant characters (rendered grouped
	// as XXXX-XXXX).
	userCodeLen = 8
	// maxAgentNameLen caps the optional requested-by hint shown on the
	// consent surface.
	maxAgentNameLen = 64
)

// DeviceAuth is a pending device authorization. It links the polled
// device_code and the human-facing user_code to the AuthSession that the
// wallet (or verification page) completes.
type DeviceAuth struct {
	DeviceCode string
	UserCode   string
	SessionID  string // AuthSession id in the shared SessionStore
	ClientID   string
	ClientName string // authoritative display name from the client registry
	// RequestedBy is an optional, caller-supplied hint naming the agent that
	// brokered the request (Mode B). It is shown to the user as an
	// UNVERIFIED "requested by" label and never conflated with ClientName.
	RequestedBy string
	Scope       string
	QRPayload   string // wallet universal link, echoed to the verification page
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Interval    int

	mu           sync.Mutex
	lastPolledAt time.Time
	denied       bool
}

// touchPoll enforces the polling interval. It returns true when the caller
// polled faster than Interval since the previous poll (RFC 8628 slow_down).
func (d *DeviceAuth) touchPoll() (tooFast bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if !d.lastPolledAt.IsZero() && now.Sub(d.lastPolledAt) < time.Duration(d.Interval)*time.Second {
		// Bump the interval per RFC 8628 §3.5 so a misbehaving client backs off.
		d.Interval += defaultDeviceInterval
		d.lastPolledAt = now
		return true
	}
	d.lastPolledAt = now
	return false
}

// DeviceStore holds pending device authorizations in memory.
type DeviceStore struct {
	mu       sync.Mutex
	byDevice map[string]*DeviceAuth
	byUser   map[string]string // user_code -> device_code
}

// NewDeviceStore creates a device store with a background cleanup loop.
func NewDeviceStore() *DeviceStore {
	ds := &DeviceStore{
		byDevice: make(map[string]*DeviceAuth),
		byUser:   make(map[string]string),
	}
	go func() {
		for {
			time.Sleep(time.Minute)
			ds.cleanup()
		}
	}()
	return ds
}

// Create stores a device authorization.
func (ds *DeviceStore) Create(d *DeviceAuth) {
	ds.mu.Lock()
	ds.byDevice[d.DeviceCode] = d
	ds.byUser[d.UserCode] = d.DeviceCode
	ds.mu.Unlock()
}

// GetByDeviceCode looks up a non-expired device authorization by device_code.
func (ds *DeviceStore) GetByDeviceCode(code string) (*DeviceAuth, bool) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	d, ok := ds.byDevice[code]
	if !ok || time.Now().After(d.ExpiresAt) {
		return nil, false
	}
	return d, true
}

// GetByUserCode looks up a non-expired device authorization by user_code.
// The user_code is normalised (upper-cased, dashes/spaces stripped) so the
// verification page can accept whatever the human types.
func (ds *DeviceStore) GetByUserCode(userCode string) (*DeviceAuth, bool) {
	norm := normalizeUserCode(userCode)
	ds.mu.Lock()
	defer ds.mu.Unlock()
	dc, ok := ds.byUser[norm]
	if !ok {
		return nil, false
	}
	d, ok := ds.byDevice[dc]
	if !ok || time.Now().After(d.ExpiresAt) {
		return nil, false
	}
	return d, true
}

// Deny marks a device authorization as rejected by the user.
func (ds *DeviceStore) Deny(userCode string) bool {
	d, ok := ds.GetByUserCode(userCode)
	if !ok {
		return false
	}
	d.mu.Lock()
	d.denied = true
	d.mu.Unlock()
	return true
}

// Delete removes a device authorization (after tokens are issued).
func (ds *DeviceStore) Delete(deviceCode string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if d, ok := ds.byDevice[deviceCode]; ok {
		delete(ds.byUser, d.UserCode)
		delete(ds.byDevice, deviceCode)
	}
}

func (ds *DeviceStore) cleanup() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	now := time.Now()
	for code, d := range ds.byDevice {
		if now.After(d.ExpiresAt) {
			delete(ds.byUser, d.UserCode)
			delete(ds.byDevice, code)
		}
	}
}

// HandleDeviceAuthorization implements POST /device_authorization (RFC 8628).
//
// Request (application/x-www-form-urlencoded):
//
//	client_id              required
//	scope                  optional (e.g. "openid email profile offline_access")
//	code_challenge         required (PKCE S256 — the CLI proves possession at /token)
//	code_challenge_method  optional (defaults to S256)
//	agent_name             optional (Mode B: names the brokering agent, shown unverified)
//
// Response adds Privasys extensions to the standard fields:
//
//	device_code, user_code, verification_uri, verification_uri_complete,
//	expires_in, interval, plus qr_payload (wallet universal link) and
//	requested_attributes.
func HandleDeviceAuthorization(reg *clients.Registry, sessions *SessionStore, devices *DeviceStore, issuerURL string, minter *voucher.Minter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "Cannot parse form")
			return
		}

		clientID := r.FormValue("client_id")
		scope := r.FormValue("scope")
		codeChallenge := r.FormValue("code_challenge")
		codeChallengeMethod := r.FormValue("code_challenge_method")
		agentName := sanitizeAgentName(r.FormValue("agent_name"))

		client, err := reg.Get(clientID)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_client", "Unknown client_id")
			return
		}

		// PKCE is required: the device_code is bearer-ish until approval, so
		// the polling client must prove possession of the verifier at /token.
		if codeChallenge == "" {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "code_challenge is required (PKCE)")
			return
		}
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}
		if codeChallengeMethod != "S256" {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "Only S256 code_challenge_method is supported")
			return
		}

		now := time.Now()

		// Create the AuthSession the wallet (or verification page) completes.
		// No RedirectURI: the device flow delivers the code by polling, never
		// by browser redirect — so there are no redirect URIs to allowlist.
		sessionID := generateID()
		sessions.Create(&AuthSession{
			SessionID:           sessionID,
			ClientID:            clientID,
			RedirectURI:         "",
			Scope:               scope,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			CreatedAt:           now,
			ExpiresAt:           now.Add(deviceCodeTTL),
		})

		// Wallet QR payload — same shape as /authorize so the existing wallet
		// relay completes the session unchanged. appName carries the
		// authoritative client name (consent §11.2); requestedBy carries the
		// optional, unverified agent label.
		qrPayload := map[string]interface{}{
			"origin":    "privasys.id",
			"sessionId": sessionID,
			"rpId":      "privasys.id",
			"clientId":  clientID,
			"appName":   client.ClientName,
			"brokerUrl": "wss://relay.privasys.org/relay",
		}
		if agentName != "" {
			qrPayload["requestedBy"] = agentName
		}
		requestedAttributes := requestedAttributesForScope(scope, client)
		attributeRequirements := attributeRequirementsForScope(scope, client)
		if len(requestedAttributes) > 0 {
			qrPayload["requestedAttributes"] = requestedAttributes
			qrPayload["attributeRequirements"] = attributeRequirements
		}

		// Reserve the relying party's credits for any paid (gov) attributes and
		// carry the disclosure vouchers to the wallet in the same payload.
		vouchers, mintErr := mintDisclosureVouchers(r.Context(), minter, client, attributeRequirements)
		if mintErr == voucher.ErrInsufficient {
			errorResponse(w, http.StatusPaymentRequired, "insufficient_credits",
				"The relying party has insufficient credits for the requested attributes")
			return
		} else if mintErr != nil {
			errorResponse(w, http.StatusBadGateway, "voucher_error",
				"Could not reserve attribute credits")
			return
		}
		if len(vouchers) > 0 {
			qrPayload["disclosureVouchers"] = vouchers
		}

		qrJSON, _ := json.Marshal(qrPayload)
		universalLink := "https://privasys.id/scp?p=" + base64.RawURLEncoding.EncodeToString(qrJSON)

		deviceCode := generateDeviceCode()
		userCode := generateUserCode()
		devices.Create(&DeviceAuth{
			DeviceCode:  deviceCode,
			UserCode:    userCode,
			SessionID:   sessionID,
			ClientID:    clientID,
			ClientName:  client.ClientName,
			RequestedBy: agentName,
			Scope:       scope,
			QRPayload:   universalLink,
			CreatedAt:   now,
			ExpiresAt:   now.Add(deviceCodeTTL),
			Interval:    defaultDeviceInterval,
		})

		userCodeDisplay := formatUserCode(userCode)
		resp := map[string]interface{}{
			"device_code":               deviceCode,
			"user_code":                 userCodeDisplay,
			"verification_uri":          issuerURL + "/device",
			"verification_uri_complete": issuerURL + "/device?user_code=" + userCodeDisplay,
			"expires_in":                int(deviceCodeTTL.Seconds()),
			"interval":                  defaultDeviceInterval,
			"qr_payload":                universalLink,
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

// HandleDeviceLookup implements GET /device/lookup?user_code=XXXX for the
// verification page: it returns the consent details (authoritative client
// name, the unverified requested-by label, scope, wallet link) and the
// current approval status. Public (the user_code is the capability).
func HandleDeviceLookup(devices *DeviceStore, sessions *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		da, ok := devices.GetByUserCode(r.URL.Query().Get("user_code"))
		if !ok {
			errorResponse(w, http.StatusNotFound, "invalid_request", "Unknown or expired code")
			return
		}
		status := "pending"
		if da.mu.Lock(); da.denied {
			status = "denied"
		}
		da.mu.Unlock()
		if status == "pending" {
			if s, sok := sessions.Get(da.SessionID); sok && s.Authenticated {
				status = "approved"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"client_name":  da.ClientName,
			"requested_by": da.RequestedBy,
			"scope":        da.Scope,
			"qr_payload":   da.QRPayload,
			"status":       status,
		})
	}
}

// HandleDeviceDeny implements POST /device/deny {user_code}. Lets the
// verification page reject a request so the polling client gets access_denied.
func HandleDeviceDeny(devices *DeviceStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserCode string `json:"user_code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.UserCode == "" {
			req.UserCode = r.FormValue("user_code")
		}
		if !devices.Deny(req.UserCode) {
			errorResponse(w, http.StatusNotFound, "invalid_request", "Unknown or expired code")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "denied"})
	}
}

// HandleDeviceApprove implements POST /device/approve {user_code} with a
// Bearer access token. The verification page authenticates the user with the
// @privasys/auth SDK (wallet, passkey, or social — Modes B and C), then calls
// this to approve the pending device by completing its AuthSession with the
// authenticated user. This is the non-wallet-relay approval path; the
// wallet-QR path completes the session directly via the FIDO2 relay.
func HandleDeviceApprove(issuer *tokens.Issuer, devices *DeviceStore, sessions *SessionStore, codes *CodeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			w.Header().Set("WWW-Authenticate", "Bearer")
			errorResponse(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
			return
		}
		claims, err := issuer.VerifyAccessToken(auth[7:])
		if err != nil {
			errorResponse(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}
		sub, _ := claims["sub"].(string)
		if sub == "" {
			errorResponse(w, http.StatusUnauthorized, "invalid_token", "Missing sub claim")
			return
		}

		var req struct {
			UserCode string `json:"user_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserCode == "" {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "user_code required")
			return
		}

		da, ok := devices.GetByUserCode(req.UserCode)
		if !ok {
			errorResponse(w, http.StatusNotFound, "invalid_request", "Unknown or expired code")
			return
		}
		session, ok := sessions.Get(da.SessionID)
		if !ok {
			errorResponse(w, http.StatusNotFound, "invalid_request", "Authorization expired")
			return
		}

		// Idempotent: if already approved, succeed without minting a new code.
		if !session.Authenticated {
			// Carry whatever profile attributes the page's login put in the
			// access token, so the device's token is consistent with a wallet
			// approval.
			attrs := map[string]string{}
			for _, a := range attributes.All {
				if v, ok := claims[a.Key].(string); ok && v != "" {
					attrs[a.Key] = v
				}
			}
			authCode := codes.Create(&AuthCode{
				ClientID:            session.ClientID,
				UserID:              sub,
				Scope:               session.Scope,
				CodeChallenge:       session.CodeChallenge,
				CodeChallengeMethod: session.CodeChallengeMethod,
				AuthTime:            time.Now(),
				Attributes:          attrs,
			})
			sessions.Complete(da.SessionID, sub, authCode)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
	}
}

// --- code generation & formatting ---

func generateDeviceCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateUserCode() string {
	out := make([]byte, userCodeLen)
	max := big.NewInt(int64(len(userCodeAlphabet)))
	for i := range out {
		n, _ := rand.Int(rand.Reader, max)
		out[i] = userCodeAlphabet[n.Int64()]
	}
	return string(out)
}

// formatUserCode renders the stored 8-char code grouped as XXXX-XXXX.
func formatUserCode(code string) string {
	if len(code) != userCodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// normalizeUserCode upper-cases and strips dashes/spaces so the verification
// page accepts the code however the human types it.
func normalizeUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// sanitizeAgentName trims, strips control characters, and caps the length of
// the optional agent label so it is safe to render on the consent surface.
func sanitizeAgentName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxAgentNameLen {
			break
		}
	}
	return b.String()
}
