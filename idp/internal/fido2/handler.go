// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package fido2 implements FIDO2/WebAuthn registration and authentication
// for the Privasys IdP. The wallet connects here to register hardware-bound
// credentials and authenticate via biometric-gated signing.
//
// Wire format matches the enclave's Fido2Request/Fido2Response so the
// Privasys Wallet can speak to the IdP identically to how it speaks to
// an enclave.
package fido2

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/oidc"
	"github.com/Privasys/idp/internal/recovery"
	"github.com/Privasys/idp/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

// sessionRelayBindingDomain is the version-tagged domain separator that
// prefixes the SHA-256 input used as the WebAuthn challenge in the
// session-relay flow. See `buildSessionRelayClaims` for the matching
// recompute on /complete.
const sessionRelayBindingDomain = "privasys-session-relay/v1"

// computeSessionRelayBinding hashes the canonical input defined by §3.3 of
// the session-relay design. All inputs are accepted as base64url strings
// (sdk_pub, enc_pub, nonce, session_id) or hex strings (quote_hash) and
// decoded to their raw bytes before concatenation. session_id is base64url
// because that is the encoding the enclave manager's session-bootstrap
// endpoint emits on the wire.
func computeSessionRelayBinding(nonceB64, sdkPubB64, quoteHashHex, encPubB64, sessionIDB64 string) ([]byte, error) {
	nonce, err := decodeRawURLB64(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	sdkPub, err := decodeRawURLB64(sdkPubB64)
	if err != nil {
		return nil, fmt.Errorf("sdk_pub: %w", err)
	}
	quoteHash, err := hex.DecodeString(quoteHashHex)
	if err != nil {
		return nil, fmt.Errorf("quote_hash: %w", err)
	}
	encPub, err := decodeRawURLB64(encPubB64)
	if err != nil {
		return nil, fmt.Errorf("enc_pub: %w", err)
	}
	sessionID, err := decodeRawURLB64(sessionIDB64)
	if err != nil {
		return nil, fmt.Errorf("session_id: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(sessionRelayBindingDomain))
	h.Write(nonce)
	h.Write(sdkPub)
	h.Write(quoteHash)
	h.Write(encPub)
	h.Write(sessionID)
	return h.Sum(nil), nil
}

// Config for the FIDO2 handler.
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	DB            *store.DB
}

// Handler manages FIDO2 registration and authentication.
type Handler struct {
	webAuthn       *webauthn.WebAuthn
	db             *store.DB
	challenges     *challengeStore
	walletSessions *walletSessionStore
}

// walletSessionStore is a tiny in-memory map of sessionToken → user_id with TTL.
// Issued by /fido2/*/complete and consumed by recovery management endpoints to
// avoid the wallet needing a full OIDC bearer token.
type walletSessionStore struct {
	mu       sync.Mutex
	sessions map[string]walletSessionEntry
}

type walletSessionEntry struct {
	userID    string
	expiresAt time.Time
}

const walletSessionTTL = 30 * time.Minute

func newWalletSessionStore() *walletSessionStore {
	s := &walletSessionStore{sessions: make(map[string]walletSessionEntry)}
	go func() {
		for {
			time.Sleep(time.Minute)
			s.cleanup()
		}
	}()
	return s
}

func (s *walletSessionStore) issue(userID string) string {
	token := generateToken()
	s.mu.Lock()
	s.sessions[token] = walletSessionEntry{userID: userID, expiresAt: time.Now().Add(walletSessionTTL)}
	s.mu.Unlock()
	return token
}

// Resolve returns the user_id for a sessionToken, sliding the TTL on success.
func (s *walletSessionStore) Resolve(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.sessions[token]
	if !ok || time.Now().After(e.expiresAt) {
		delete(s.sessions, token)
		return "", false
	}
	e.expiresAt = time.Now().Add(walletSessionTTL)
	s.sessions[token] = e
	return e.userID, true
}

func (s *walletSessionStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expiresAt) {
			delete(s.sessions, k)
		}
	}
}

// WalletSessionResolver returns a closure usable by the recovery package.
func (h *Handler) WalletSessionResolver() func(string) (string, bool) {
	return h.walletSessions.Resolve
}

// NewHandler creates a FIDO2 handler with the given configuration.
func NewHandler(cfg Config) (*Handler, error) {
	wconfig := &webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             cfg.RPOrigins,
		AttestationPreference: protocol.PreferDirectAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		},
	}

	w, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}

	return &Handler{
		webAuthn:       w,
		db:             cfg.DB,
		challenges:     newChallengeStore(),
		walletSessions: newWalletSessionStore(),
	}, nil
}

// --- User adapter for go-webauthn ---

type idpUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *idpUser) WebAuthnID() []byte                         { return u.ID }
func (u *idpUser) WebAuthnName() string                       { return u.Name }
func (u *idpUser) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *idpUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// --- Challenge store ---

type challengeEntry struct {
	sessionData  *webauthn.SessionData
	user         *idpUser
	sessionID    string // OIDC authorization session ID
	discoverable bool   // true when authenticate/begin had no credentialId
	expiresAt    time.Time
}

type challengeStore struct {
	mu         sync.Mutex
	challenges map[string]*challengeEntry
}

func newChallengeStore() *challengeStore {
	cs := &challengeStore{challenges: make(map[string]*challengeEntry)}
	go func() {
		for {
			time.Sleep(time.Minute)
			cs.cleanup()
		}
	}()
	return cs
}

func (cs *challengeStore) put(key string, entry *challengeEntry) {
	cs.mu.Lock()
	cs.challenges[key] = entry
	cs.mu.Unlock()
}

func (cs *challengeStore) pop(key string) (*challengeEntry, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	e, ok := cs.challenges[key]
	if !ok || time.Now().After(e.expiresAt) {
		delete(cs.challenges, key)
		return nil, false
	}
	delete(cs.challenges, key)
	return e, true
}

func (cs *challengeStore) cleanup() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := time.Now()
	for k, v := range cs.challenges {
		if now.After(v.expiresAt) {
			delete(cs.challenges, k)
		}
	}
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func errorJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"type": "error", "error": msg})
}

func generateUserID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- Registration ---

// BeginRegistration handles POST /fido2/register/begin?session_id=...
//
// Returns standard WebAuthn PublicKeyCredentialCreationOptions.
//
// Request body:
//
//	{"userName": "...", "userHandle": "..."}
//
// Response (standard CredentialCreation — go-webauthn native JSON):
//
//	{"publicKey": {"rp": {...}, "user": {...}, "challenge": "...", ...}}
func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")

	// Optional binding-challenge override for the session-relay flow.
	// See BeginAuthentication for the rationale.
	bindingChallengeStr := r.URL.Query().Get("binding_challenge")
	var bindingChallengeBytes []byte
	if bindingChallengeStr != "" {
		var err error
		bindingChallengeBytes, err = decodeRawURLB64(bindingChallengeStr)
		if err != nil || len(bindingChallengeBytes) != 32 {
			errorJSON(w, http.StatusBadRequest, "invalid binding_challenge")
			return
		}
	}

	var req struct {
		UserName   string `json:"userName"`
		UserHandle string `json:"userHandle"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID := req.UserHandle
	if userID == "" {
		userID = generateUserID()
	}

	// Ensure user exists in DB.
	_, err := h.db.Exec(`
		INSERT INTO users (user_id) VALUES (?)
		ON CONFLICT(user_id) DO UPDATE SET
			updated_at = CURRENT_TIMESTAMP
	`, userID)
	if err != nil {
		log.Printf("fido2/register/begin: user upsert failed: %v", err)
		errorJSON(w, http.StatusInternalServerError, "database error")
		return
	}

	existingCreds, err := h.loadCredentials(userID)
	if err != nil {
		log.Printf("fido2/register/begin: load credentials failed: %v", err)
	}

	user := &idpUser{
		ID:          []byte(userID),
		Name:        req.UserName,
		DisplayName: req.UserName,
		Credentials: existingCreds,
	}

	options, sessionData, err := h.webAuthn.BeginRegistration(user)
	if err != nil {
		log.Printf("fido2/register/begin: %v", err)
		errorJSON(w, http.StatusInternalServerError, "registration failed")
		return
	}

	if bindingChallengeBytes != nil {
		options.Response.Challenge = protocol.URLEncodedBase64(bindingChallengeBytes)
		sessionData.Challenge = bindingChallengeStr
	}

	challengeKey := sessionData.Challenge
	h.challenges.put(challengeKey, &challengeEntry{
		sessionData: sessionData,
		user:        user,
		sessionID:   sessionID,
		expiresAt:   time.Now().Add(5 * time.Minute),
	})

	// Return standard WebAuthn CredentialCreation options.
	writeJSON(w, options)
}

// CompleteRegistration handles POST /fido2/register/complete?challenge=...
//
// The request body is a standard WebAuthn AuthenticatorAttestationResponse.
// go-webauthn parses and verifies it directly from the request.
//
// Request body (standard WebAuthn):
//
//	{"id": "...", "rawId": "...", "type": "public-key",
//	 "response": {"clientDataJSON": "...", "attestationObject": "..."}}
//
// Response:
//
//	{"status": "ok", "sessionToken": "..."}
func (h *Handler) CompleteRegistration(
	codeStore *oidc.CodeStore,
	sessionStore *oidc.SessionStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("challenge")
		if challenge == "" {
			errorJSON(w, http.StatusBadRequest, "missing challenge parameter")
			return
		}

		entry, ok := h.challenges.pop(challenge)
		if !ok {
			errorJSON(w, http.StatusBadRequest, "challenge expired or not found")
			return
		}

		// Enforce session-relay binding before any side effect.
		if err := enforceSessionRelayBinding(r, challenge); err != nil {
			log.Printf("fido2/register/complete: %v", err)
			errorJSON(w, http.StatusBadRequest, "session-relay binding invalid")
			return
		}

		// Body is standard WebAuthn JSON — go-webauthn reads it directly.
		credential, err := h.webAuthn.FinishRegistration(entry.user, *entry.sessionData, r)
		if err != nil {
			log.Printf("fido2/register/complete: %v", err)
			errorJSON(w, http.StatusBadRequest, fmt.Sprintf("registration verification failed: %s", err))
			return
		}

		// Validate that the public key is parseable — go-webauthn with "none"
		// attestation does not parse the key during registration.
		if _, err := webauthncose.ParsePublicKey(credential.PublicKey); err != nil {
			log.Printf("fido2/register/complete: credential public key is not parseable (len=%d): %v",
				len(credential.PublicKey), err)
			errorJSON(w, http.StatusBadRequest, "registration failed: unsupported public key format")
			return
		}

		// Store credential in DB.
		credID := base64.RawURLEncoding.EncodeToString(credential.ID)
		pubKeyBytes := credential.PublicKey // raw COSE key bytes
		aaguid := hex.EncodeToString(credential.Authenticator.AAGUID)

		_, err = h.db.Exec(`
			INSERT INTO credentials (credential_id, user_id, public_key, aaguid, sign_count, attestation_type)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(credential_id) DO UPDATE SET
				public_key = excluded.public_key,
				aaguid = excluded.aaguid,
				sign_count = excluded.sign_count,
				attestation_type = excluded.attestation_type
			WHERE credentials.user_id = excluded.user_id
		`, credID, string(entry.user.ID), pubKeyBytes, aaguid,
			credential.Authenticator.SignCount, credential.AttestationType)
		if err != nil {
			log.Printf("fido2/register/complete: store credential: %v", err)
			errorJSON(w, http.StatusInternalServerError, "credential storage failed")
			return
		}

		userID := string(entry.user.ID)
		log.Printf("fido2: registered credential %s for user %s (aaguid: %s)",
			credID[:16]+"...", userID, aaguid)

		// Issue a wallet session token for management ops (recovery phrase, etc).
		sessionToken := h.walletSessions.issue(userID)

		// On first registration, auto-generate a BIP39 recovery phrase if the
		// user has none. Returned ONCE; user must save it.
		var recoveryPhrase string
		if existing, _ := h.db.HasRecoveryCodes(userID); existing == 0 {
			if phrase, err := recovery.GenerateRecoveryPhrase(); err == nil {
				if err := h.db.StoreRecoveryCodes(userID, []string{recovery.HashPhrase(phrase)}); err == nil {
					recoveryPhrase = phrase
				} else {
					log.Printf("fido2/register/complete: store recovery phrase: %v", err)
				}
			} else {
				log.Printf("fido2/register/complete: generate recovery phrase: %v", err)
			}
		}

		// Mark OIDC session complete (first-time users register, not authenticate).
		if entry.sessionID != "" {
			session, ok := sessionStore.Get(entry.sessionID)
			if ok {
				relay := buildSessionRelayClaims(r)
				authCode := codeStore.Create(&oidc.AuthCode{
					ClientID:            session.ClientID,
					RedirectURI:         session.RedirectURI,
					UserID:              userID,
					Scope:               session.Scope,
					Nonce:               session.Nonce,
					CodeChallenge:       session.CodeChallenge,
					CodeChallengeMethod: session.CodeChallengeMethod,
					AuthTime:            time.Now(),
					SessionRelay:        relay,
				})
				sessionStore.Complete(entry.sessionID, userID, authCode)
			}
		}

		resp := map[string]interface{}{
			"status":       "ok",
			"sessionToken": sessionToken,
			"userId":       userID,
		}
		if recoveryPhrase != "" {
			resp["recoveryPhrase"] = recoveryPhrase
		}
		writeJSON(w, resp)
	}
}

// --- Authentication ---

// BeginAuthentication handles POST /fido2/authenticate/begin?session_id=...
//
// Returns standard WebAuthn PublicKeyCredentialRequestOptions.
//
// Request body:
//
//	{"credentialId": "..."}
//
// Response (standard CredentialAssertion — go-webauthn native JSON):
//
//	{"publicKey": {"challenge": "...", "rpId": "...", "allowCredentials": [...], ...}}
func (h *Handler) BeginAuthentication(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")

	// Optional: when the client is using the session-relay flow it
	// pre-computes the WebAuthn challenge as a SHA-256 binding over
	// (nonce, sdk_pub, quote_hash, enc_pub, session_id) and supplies it
	// here as a base64url string. We override the random challenge that
	// go-webauthn would generate so the assertion is provably bound to
	// the relay parameters. The same value is recomputed and re-checked
	// on /complete.
	bindingChallengeStr := r.URL.Query().Get("binding_challenge")
	var bindingChallengeBytes []byte
	if bindingChallengeStr != "" {
		var err error
		bindingChallengeBytes, err = decodeRawURLB64(bindingChallengeStr)
		if err != nil || len(bindingChallengeBytes) != 32 {
			errorJSON(w, http.StatusBadRequest, "invalid binding_challenge")
			return
		}
	}

	var req struct {
		CredentialID string `json:"credentialId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Discoverable credential flow: when no credentialId is provided,
	// start a discoverable login so the browser offers all stored
	// passkeys for this RP.
	if req.CredentialID == "" {
		options, sessionData, err := h.webAuthn.BeginDiscoverableLogin()
		if err != nil {
			log.Printf("fido2/authenticate/begin (discoverable): %v", err)
			errorJSON(w, http.StatusInternalServerError, "authentication failed")
			return
		}

		if bindingChallengeBytes != nil {
			options.Response.Challenge = protocol.URLEncodedBase64(bindingChallengeBytes)
			sessionData.Challenge = bindingChallengeStr
		}

		challengeKey := sessionData.Challenge
		h.challenges.put(challengeKey, &challengeEntry{
			sessionData:  sessionData,
			user:         nil, // resolved during FinishDiscoverableLogin
			sessionID:    sessionID,
			discoverable: true,
			expiresAt:    time.Now().Add(5 * time.Minute),
		})

		writeJSON(w, options)
		return
	}

	// Standard flow: look up user by credential ID.
	var userID string
	err := h.db.QueryRow(
		"SELECT user_id FROM credentials WHERE credential_id = ?",
		req.CredentialID,
	).Scan(&userID)
	if err != nil {
		errorJSON(w, http.StatusNotFound, "no credentials found for user")
		return
	}

	creds, err := h.loadCredentials(userID)
	if err != nil || len(creds) == 0 {
		errorJSON(w, http.StatusNotFound, "no credentials found for user")
		return
	}

	user := &idpUser{
		ID:          []byte(userID),
		Name:        userID,
		Credentials: creds,
	}

	options, sessionData, err := h.webAuthn.BeginLogin(user)
	if err != nil {
		log.Printf("fido2/authenticate/begin: %v", err)
		errorJSON(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	if bindingChallengeBytes != nil {
		options.Response.Challenge = protocol.URLEncodedBase64(bindingChallengeBytes)
		sessionData.Challenge = bindingChallengeStr
	}

	challengeKey := sessionData.Challenge
	h.challenges.put(challengeKey, &challengeEntry{
		sessionData: sessionData,
		user:        user,
		sessionID:   sessionID,
		expiresAt:   time.Now().Add(5 * time.Minute),
	})

	// Return standard WebAuthn CredentialAssertion.
	writeJSON(w, options)
}

// CompleteAuthentication handles POST /fido2/authenticate/complete?challenge=...
//
// The request body is a standard WebAuthn AuthenticatorAssertionResponse.
// go-webauthn parses and verifies it directly from the request.
//
// Request body (standard WebAuthn):
//
//	{"id": "...", "rawId": "...", "type": "public-key",
//	 "response": {"clientDataJSON": "...", "authenticatorData": "...", "signature": "..."}}
//
// Response:
//
//	{"status": "ok", "sessionToken": "..."}
func (h *Handler) CompleteAuthentication(
	codeStore *oidc.CodeStore,
	sessionStore *oidc.SessionStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("challenge")
		if challenge == "" {
			errorJSON(w, http.StatusBadRequest, "missing challenge parameter")
			return
		}

		entry, ok := h.challenges.pop(challenge)
		if !ok {
			errorJSON(w, http.StatusBadRequest, "challenge expired or not found")
			return
		}

		// Enforce session-relay binding before any side effect.
		if err := enforceSessionRelayBinding(r, challenge); err != nil {
			log.Printf("fido2/authenticate/complete: %v", err)
			errorJSON(w, http.StatusBadRequest, "session-relay binding invalid")
			return
		}

		var credential *webauthn.Credential
		var userID string

		if entry.discoverable {
			// Discoverable credential flow: resolve user from the assertion.
			handler := func(rawID, userHandle []byte) (webauthn.User, error) {
				credIDStr := base64.RawURLEncoding.EncodeToString(rawID)
				var uid string
				err := h.db.QueryRow(
					"SELECT user_id FROM credentials WHERE credential_id = ?",
					credIDStr,
				).Scan(&uid)
				if err != nil {
					return nil, fmt.Errorf("credential not found: %w", err)
				}
				creds, err := h.loadCredentials(uid)
				if err != nil || len(creds) == 0 {
					return nil, fmt.Errorf("no credentials for user")
				}
				return &idpUser{
					ID:          []byte(uid),
					Name:        uid,
					Credentials: creds,
				}, nil
			}

			cred, err := h.webAuthn.FinishDiscoverableLogin(handler, *entry.sessionData, r)
			if err != nil {
				log.Printf("fido2/authenticate/complete (discoverable): %v", err)
				errorJSON(w, http.StatusBadRequest, fmt.Sprintf("authentication verification failed: %s", err))
				return
			}
			credential = cred

			// Resolve user ID from the credential.
			credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
			if err := h.db.QueryRow(
				"SELECT user_id FROM credentials WHERE credential_id = ?",
				credIDStr,
			).Scan(&userID); err != nil {
				log.Printf("fido2/authenticate/complete: user lookup failed: %v", err)
				errorJSON(w, http.StatusInternalServerError, "user lookup failed")
				return
			}
		} else {
			// Standard flow: user was resolved during BeginLogin.
			cred, err := h.webAuthn.FinishLogin(entry.user, *entry.sessionData, r)
			if err != nil {
				log.Printf("fido2/authenticate/complete: %v", err)
				errorJSON(w, http.StatusBadRequest, fmt.Sprintf("authentication verification failed: %s", err))
				return
			}
			credential = cred
			userID = string(entry.user.ID)
		}

		credID := base64.RawURLEncoding.EncodeToString(credential.ID)
		h.db.Exec("UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
			credential.Authenticator.SignCount, credID)

		log.Printf("fido2: authenticated user %s (credential %s...)", userID, credID[:16])

		sessionToken := h.walletSessions.issue(userID)

		// Generate OIDC auth code and mark session complete.
		if entry.sessionID != "" {
			session, ok := sessionStore.Get(entry.sessionID)
			if ok {
				relay := buildSessionRelayClaims(r)
				authCode := codeStore.Create(&oidc.AuthCode{
					ClientID:            session.ClientID,
					RedirectURI:         session.RedirectURI,
					UserID:              userID,
					Scope:               session.Scope,
					Nonce:               session.Nonce,
					CodeChallenge:       session.CodeChallenge,
					CodeChallengeMethod: session.CodeChallengeMethod,
					AuthTime:            time.Now(),
					SessionRelay:        relay,
				})
				sessionStore.Complete(entry.sessionID, userID, authCode)
			}
		}

		writeJSON(w, map[string]interface{}{
			"status":       "ok",
			"sessionToken": sessionToken,
			"userId":       userID,
		})
	}
}

// --- DB helpers ---

func (h *Handler) loadCredentials(userID string) ([]webauthn.Credential, error) {
	rows, err := h.db.Query(
		"SELECT credential_id, public_key, aaguid, sign_count FROM credentials WHERE user_id = ?",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []webauthn.Credential
	for rows.Next() {
		var credIDStr, aaguidStr string
		var pubKeyBytes []byte
		var signCount uint32

		if err := rows.Scan(&credIDStr, &pubKeyBytes, &aaguidStr, &signCount); err != nil {
			continue
		}

		credID, _ := base64.RawURLEncoding.DecodeString(credIDStr)
		aaguid, _ := hex.DecodeString(aaguidStr)

		cred := webauthn.Credential{
			ID:              credID,
			PublicKey:       pubKeyBytes,
			AttestationType: "none",
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: signCount,
			},
		}
		creds = append(creds, cred)
	}

	return creds, nil
}

// buildSessionRelayClaims extracts the optional browser→enclave session
// relay metadata from the request's URL query parameters and returns a
// claim map ready to embed into the AuthCode. Returns nil when no
// session_id is present (the canonical signal that this is not a
// session-relay flow).
//
// Callers MUST have already validated the binding challenge (see
// enforceSessionRelayBinding) before invoking this — the claims
// returned here carry `att_verified: true` which downstream relying
// parties trust as proof that the wallet attested the listed quote.
func buildSessionRelayClaims(r *http.Request) map[string]interface{} {
	q := r.URL.Query()
	sid := q.Get("session_id")
	if sid == "" {
		return nil
	}
	relay := map[string]interface{}{
		"att_verified": true,
		"session": map[string]interface{}{
			"id":           sid,
			"enc_pub":      q.Get("enc_pub"),
			"sdk_pub_bind": q.Get("sdk_pub"),
			"quote_hash":   q.Get("quote_hash"),
		},
	}
	if qh := q.Get("quote_hash"); qh != "" {
		relay["att_quote_hash"] = qh
	}
	if oids := q.Get("att_oids"); oids != "" {
		relay["att_oids"] = oids
	}
	return relay
}

// decodeRawURLB64 accepts both padded and unpadded URL-safe base64 input.
func decodeRawURLB64(s string) ([]byte, error) {
	// strip trailing '=' padding then use RawURLEncoding (which rejects padding)
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// enforceSessionRelayBinding validates the session-relay flow on
// /fido2/.../complete: when `session_id` is present in the query, all
// the other binding inputs (`nonce`, `sdk_pub`, `enc_pub`,
// `quote_hash`) MUST also be present, the recomputed binding hash MUST
// match `expectedChallenge` (the challenge popped from the store, which
// is the one the WebAuthn assertion signed). If any check fails, an
// error is returned and the caller MUST reject the request.
//
// When `session_id` is absent (legacy non-relay flow) this is a no-op
// and returns nil.
func enforceSessionRelayBinding(r *http.Request, expectedChallenge string) error {
	q := r.URL.Query()
	sid := q.Get("session_id")
	if sid == "" {
		return nil
	}
	nonce := q.Get("nonce")
	sdkPub := q.Get("sdk_pub")
	encPub := q.Get("enc_pub")
	quoteHash := q.Get("quote_hash")
	if nonce == "" || sdkPub == "" || encPub == "" || quoteHash == "" {
		return fmt.Errorf("session-relay flow missing binding inputs")
	}
	expected, err := computeSessionRelayBinding(nonce, sdkPub, quoteHash, encPub, sid)
	if err != nil {
		return fmt.Errorf("recompute binding: %w", err)
	}
	got, err := decodeRawURLB64(expectedChallenge)
	if err != nil {
		return fmt.Errorf("decode challenge: %w", err)
	}
	if subtle.ConstantTimeCompare(expected, got) != 1 {
		return fmt.Errorf("session-relay binding mismatch")
	}
	return nil
}
