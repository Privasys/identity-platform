// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package fido2 implements FIDO2/WebAuthn registration and authentication
// for the Privasys IdP. The wallet connects here to register hardware-bound
// credentials and authenticate via biometric-gated signing.
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
			UserVerification: protocol.VerificationRequired,
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

// idpUser implements webauthn.User for the go-webauthn library.
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
	sessionData *webauthn.SessionData
	user        *idpUser
	sessionID   string // Authorization session ID (for linking to OIDC flow)
	expiresAt   time.Time
}

type challengeStore struct {
	mu         sync.Mutex
	challenges map[string]*challengeEntry // keyed by challenge string
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

// --- Registration ---

// BeginRegistration handles POST /fido2/register/begin.
// The wallet calls this to start a new credential registration.
func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string `json:"user_id"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		SessionID   string `json:"session_id"` // OIDC authorization session
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Generate user ID if not provided.
	if req.UserID == "" {
		req.UserID = generateUserID()
	}

	// Ensure user exists in DB.
	_, err := h.db.Exec(`
		INSERT INTO users (user_id, display_name, email) VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET 
			display_name = CASE WHEN excluded.display_name != '' THEN excluded.display_name ELSE users.display_name END,
			email = CASE WHEN excluded.email != '' THEN excluded.email ELSE users.email END,
			updated_at = CURRENT_TIMESTAMP
	`, req.UserID, req.DisplayName, req.Email)
	if err != nil {
		log.Printf("fido2/register/begin: user upsert failed: %v", err)
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}

	// Load existing credentials for exclusion.
	existingCreds, err := h.loadCredentials(req.UserID)
	if err != nil {
		log.Printf("fido2/register/begin: load credentials failed: %v", err)
	}

	user := &idpUser{
		ID:          []byte(req.UserID),
		Name:        req.Email,
		DisplayName: req.DisplayName,
		Credentials: existingCreds,
	}

	options, sessionData, err := h.webAuthn.BeginRegistration(user)
	if err != nil {
		log.Printf("fido2/register/begin: %v", err)
		http.Error(w, `{"error":"registration failed"}`, http.StatusInternalServerError)
		return
	}

	// Store challenge for verification.
	challengeKey := sessionData.Challenge
	h.challenges.put(challengeKey, &challengeEntry{
		sessionData: sessionData,
		user:        user,
		sessionID:   req.SessionID,
		expiresAt:   time.Now().Add(5 * time.Minute),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"options":       options,
		"challenge_key": challengeKey,
		"user_id":       req.UserID,
	})
}

// CompleteRegistration handles POST /fido2/register/complete.
func (h *Handler) CompleteRegistration(w http.ResponseWriter, r *http.Request) {
	challengeKey := r.URL.Query().Get("challenge_key")
	if challengeKey == "" {
		challengeKey = r.Header.Get("X-Challenge-Key")
	}

	if challengeKey == "" {
		http.Error(w, `{"error":"challenge_key required"}`, http.StatusBadRequest)
		return
	}

	entry, ok := h.challenges.pop(challengeKey)
	if !ok {
		http.Error(w, `{"error":"challenge expired or not found"}`, http.StatusBadRequest)
		return
	}

	credential, err := h.webAuthn.FinishRegistration(entry.user, *entry.sessionData, r)
	if err != nil {
		log.Printf("fido2/register/complete: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"registration verification failed: %s"}`, err), http.StatusBadRequest)
		return
	}

	// Store credential in DB.
	credID := base64.RawURLEncoding.EncodeToString(credential.ID)
	pubKeyBytes, _ := json.Marshal(credential.PublicKey)
	aaguid := hex.EncodeToString(credential.Authenticator.AAGUID)

	_, err = h.db.Exec(`
		INSERT INTO credentials (credential_id, user_id, public_key, aaguid, sign_count, attestation_type)
		VALUES (?, ?, ?, ?, ?, ?)
	`, credID, string(entry.user.ID), pubKeyBytes, aaguid,
		credential.Authenticator.SignCount, credential.AttestationType)
	if err != nil {
		log.Printf("fido2/register/complete: store credential: %v", err)
		http.Error(w, `{"error":"credential storage failed"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("fido2: registered credential %s for user %s (aaguid: %s)",
		credID[:16]+"...", string(entry.user.ID), aaguid)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"credential_id": credID,
		"user_id":       string(entry.user.ID),
	})
}

// --- Authentication ---

// BeginAuthentication handles POST /fido2/authenticate/begin.
func (h *Handler) BeginAuthentication(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    string `json:"user_id"`
		SessionID string `json:"session_id"` // OIDC authorization session
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.UserID == "" {
		http.Error(w, `{"error":"user_id required"}`, http.StatusBadRequest)
		return
	}

	// Load user's credentials.
	creds, err := h.loadCredentials(req.UserID)
	if err != nil || len(creds) == 0 {
		http.Error(w, `{"error":"no credentials found for user"}`, http.StatusNotFound)
		return
	}

	user := &idpUser{
		ID:          []byte(req.UserID),
		Name:        req.UserID,
		Credentials: creds,
	}

	options, sessionData, err := h.webAuthn.BeginLogin(user)
	if err != nil {
		log.Printf("fido2/authenticate/begin: %v", err)
		http.Error(w, `{"error":"authentication failed"}`, http.StatusInternalServerError)
		return
	}

	challengeKey := sessionData.Challenge
	h.challenges.put(challengeKey, &challengeEntry{
		sessionData: sessionData,
		user:        user,
		sessionID:   req.SessionID,
		expiresAt:   time.Now().Add(5 * time.Minute),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"options":       options,
		"challenge_key": challengeKey,
	})
}

// CompleteAuthentication handles POST /fido2/authenticate/complete.
// On success, it generates an authorization code and marks the OIDC session as authenticated.
func (h *Handler) CompleteAuthentication(
	codeStore *oidc.CodeStore,
	sessionStore *oidc.SessionStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challengeKey := r.URL.Query().Get("challenge_key")
		if challengeKey == "" {
			challengeKey = r.Header.Get("X-Challenge-Key")
		}
		if challengeKey == "" {
			http.Error(w, `{"error":"challenge_key required"}`, http.StatusBadRequest)
			return
		}

		entry, ok := h.challenges.pop(challengeKey)
		if !ok {
			http.Error(w, `{"error":"challenge expired or not found"}`, http.StatusBadRequest)
			return
		}

		credential, err := h.webAuthn.FinishLogin(entry.user, *entry.sessionData, r)
		if err != nil {
			log.Printf("fido2/authenticate/complete: %v", err)
			http.Error(w, fmt.Sprintf(`{"error":"authentication verification failed: %s"}`, err),
				http.StatusBadRequest)
			return
		}

		// Update sign count.
		credID := base64.RawURLEncoding.EncodeToString(credential.ID)
		h.db.Exec("UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
			credential.Authenticator.SignCount, credID)

		userID := string(entry.user.ID)
		log.Printf("fido2: authenticated user %s (credential %s...)", userID, credID[:16])

		resp := map[string]interface{}{
			"status":  "ok",
			"user_id": userID,
		}

		// If this is part of an OIDC authorization flow, generate an auth code.
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

				resp["auth_code"] = authCode
				resp["redirect_uri"] = session.RedirectURI +
					"?code=" + authCode +
					"&state=" + session.State
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
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

		var pubKey interface{}
		json.Unmarshal(pubKeyBytes, &pubKey)

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

func generateUserID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
