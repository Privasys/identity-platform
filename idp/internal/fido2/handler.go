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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/oidc"
	"github.com/Privasys/idp/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config for the FIDO2 handler.
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	DB            *store.DB
}

// Handler manages FIDO2 registration and authentication.
type Handler struct {
	webAuthn   *webauthn.WebAuthn
	db         *store.DB
	challenges *challengeStore
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
		webAuthn:   w,
		db:         cfg.DB,
		challenges: newChallengeStore(),
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
		INSERT INTO users (user_id, display_name, email) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			display_name = CASE WHEN excluded.display_name != '' THEN excluded.display_name ELSE users.display_name END,
			updated_at = CURRENT_TIMESTAMP
	`, userID, req.UserName, "")
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

		sessionToken := generateToken()

		// Mark OIDC session complete (first-time users register, not authenticate).
		if entry.sessionID != "" {
			session, ok := sessionStore.Get(entry.sessionID)
			if ok {
				authCode := codeStore.Create(&oidc.AuthCode{
					ClientID:            session.ClientID,
					RedirectURI:         session.RedirectURI,
					UserID:              userID,
					Scope:               session.Scope,
					Nonce:               session.Nonce,
					CodeChallenge:       session.CodeChallenge,
					CodeChallengeMethod: session.CodeChallengeMethod,
					AuthTime:            time.Now(),
				})
				sessionStore.Complete(entry.sessionID, userID, authCode)
			}
		}

		writeJSON(w, map[string]interface{}{
			"status":       "ok",
			"sessionToken": sessionToken,
		})
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

		sessionToken := generateToken()

		// Generate OIDC auth code and mark session complete.
		if entry.sessionID != "" {
			session, ok := sessionStore.Get(entry.sessionID)
			if ok {
				authCode := codeStore.Create(&oidc.AuthCode{
					ClientID:            session.ClientID,
					RedirectURI:         session.RedirectURI,
					UserID:              userID,
					Scope:               session.Scope,
					Nonce:               session.Nonce,
					CodeChallenge:       session.CodeChallenge,
					CodeChallengeMethod: session.CodeChallengeMethod,
					AuthTime:            time.Now(),
				})
				sessionStore.Complete(entry.sessionID, userID, authCode)
			}
		}

		writeJSON(w, map[string]interface{}{
			"status":       "ok",
			"sessionToken": sessionToken,
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
