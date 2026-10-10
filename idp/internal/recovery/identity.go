// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/store"
)

// Identity recovery: getting back ONE identity, by proving it is yours, without
// saying which other identities are yours too.
//
// The wallet presents a different identity to each relying party, and only the
// wallet knows they belong to one person. A phrase recovery restores the main
// (canonical) account; the per-service identities used to be lost with the
// phone, because their handles were random and nothing could prove ownership.
//
// Now each identity registers, once, an Ed25519 public key the wallet derives
// from its seed and the relying party. On a new phone the wallet re-derives the
// private key and signs a challenge for that identity; a valid signature
// completes a recovery for that identity alone, which lets the new phone
// register a passkey on it (the takeover gate in fido2/register/begin). The
// server sees a sequence of unrelated recoveries: the keys are independent to
// anyone without the seed, and nothing in a request names another identity.

const (
	identityChallengeTTL = 5 * time.Minute
	// identityRecoveryDomain separates these signatures from any other use of
	// the key. The signed message is domain ‖ 0 ‖ user_id ‖ 0 ‖ challenge.
	identityRecoveryDomain = "privasys-identity-recovery/v1"

	// Attempts per rolling day. A holder recovering after a lost phone brings
	// back a handful of identities from one address, one at a time as they
	// sign in; these leave room for that and stop a scan.
	identityAttemptsPerIP       = 60
	identityAttemptsPerIdentity = 10
	phraseAttemptsPerIP         = 20
)

type identityChallenge struct {
	userID    string
	expiresAt time.Time
}

type identityChallengeStore struct {
	mu sync.Mutex
	m  map[string]identityChallenge // hex(challenge) → entry
}

func newIdentityChallengeStore() *identityChallengeStore {
	return &identityChallengeStore{m: make(map[string]identityChallenge)}
}

func (s *identityChallengeStore) put(challenge []byte, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expiresAt) {
			delete(s.m, k)
		}
	}
	s.m[hex.EncodeToString(challenge)] = identityChallenge{userID: userID, expiresAt: now.Add(identityChallengeTTL)}
}

// pop returns the challenge's identity and forgets it, so a challenge is used
// at most once, whatever the outcome.
func (s *identityChallengeStore) pop(challenge []byte) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(challenge)
	e, ok := s.m[key]
	delete(s.m, key)
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.userID, true
}

// IdentityRecoveryMessage is the exact byte string an identity's recovery key
// signs. Exported for tests and to document the contract with the wallet.
func IdentityRecoveryMessage(userID string, challenge []byte) []byte {
	msg := make([]byte, 0, len(identityRecoveryDomain)+len(userID)+len(challenge)+2)
	msg = append(msg, identityRecoveryDomain...)
	msg = append(msg, 0)
	msg = append(msg, userID...)
	msg = append(msg, 0)
	return append(msg, challenge...)
}

func decodeB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// HandleSetIdentityKey registers the calling identity's recovery public key.
// PUT /recovery/identity-key  {"public_key": "<base64url, 32 bytes>"}
// (requires the identity's own wallet session or JWT bearer)
//
// Set once. The same key again answers 200; a different one 409, so a stolen
// session cannot swap in a key of its own.
func (h *Handler) HandleSetIdentityKey(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	pub, err := decodeB64URL(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "public_key must be a base64url Ed25519 public key"})
		return
	}
	switch err := h.db.SetIdentityRecoveryKey(userID, pub); {
	case errors.Is(err, store.ErrRecoveryKeyMismatch):
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case err != nil:
		log.Printf("[recovery] set identity key: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	default:
		writeJSONStatus(w, http.StatusOK, map[string]any{"status": "stored"})
	}
}

// HandleBeginIdentityRecovery issues a challenge for one identity.
// POST /recovery/identity/begin  {"user_id": "..."}
// → 200 {"challenge": "<base64url>", "expires_in": 300}
// → 404 when the identity has no recovery key (it predates them, or never existed)
func (h *Handler) HandleBeginIdentityRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.UserID == "" || len(req.UserID) > 128 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "user_id is required"})
		return
	}
	if !h.allow(w, r, "identity-ip", clientIP(r), identityAttemptsPerIP) ||
		!h.allow(w, r, "identity-user", req.UserID, identityAttemptsPerIdentity) {
		return
	}
	pub, err := h.db.GetIdentityRecoveryKey(req.UserID)
	if err != nil {
		log.Printf("[recovery] identity key lookup: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if pub == nil {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "this identity has no recovery key"})
		return
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	h.identityChallenges.put(challenge, req.UserID)
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"challenge":  base64.RawURLEncoding.EncodeToString(challenge),
		"expires_in": int(identityChallengeTTL.Seconds()),
	})
}

// HandleCompleteIdentityRecovery verifies the signature and completes a
// recovery for that identity: its old passkeys and sessions are revoked, and
// for the next hour the caller may register a new passkey on it.
// POST /recovery/identity/complete
// {"user_id": "...", "challenge": "<base64url>", "signature": "<base64url>"}
func (h *Handler) HandleCompleteIdentityRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    string `json:"user_id"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.UserID == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "user_id, challenge and signature are required"})
		return
	}
	challenge, err1 := decodeB64URL(req.Challenge)
	sig, err2 := decodeB64URL(req.Signature)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "challenge and signature must be base64url"})
		return
	}
	owner, ok := h.identityChallenges.pop(challenge)
	if !ok || owner != req.UserID {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "challenge expired or not issued for this identity"})
		return
	}
	pub, err := h.db.GetIdentityRecoveryKey(req.UserID)
	if err != nil || pub == nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "this identity has no recovery key"})
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), IdentityRecoveryMessage(req.UserID, challenge), sig) {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "signature does not match this identity's recovery key"})
		return
	}

	requestID := GenerateID()
	if err := h.db.CreateRecoveryRequest(requestID, req.UserID, 0, time.Now().Add(time.Hour)); err != nil {
		log.Printf("[recovery] identity request: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if err := h.db.UpdateRecoveryCodeVerified(requestID); err != nil {
		log.Printf("[recovery] identity request verify: %v", err)
	}
	if err := h.db.CompleteRecovery(requestID, req.UserID); err != nil {
		log.Printf("[recovery] identity complete: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "completed", "user_id": req.UserID})
}

// allow counts an attempt against key and answers 429 once the day's limit is
// reached. The key is stored hashed: the table holds no addresses or ids.
func (h *Handler) allow(w http.ResponseWriter, r *http.Request, kind, value string, limit int) bool {
	sum := sha256.Sum256([]byte(kind + "\x00" + value))
	key := hex.EncodeToString(sum[:])
	n, err := h.db.CheckRecoveryRateLimit(key)
	if err != nil {
		log.Printf("[recovery] rate limit check: %v", err)
		return true // a broken counter must not lock holders out
	}
	if n >= limit {
		w.Header().Set("Retry-After", "3600")
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{"error": "too many recovery attempts; try again later"})
		return false
	}
	if err := h.db.RecordRecoveryAttempt(key); err != nil {
		log.Printf("[recovery] rate limit record: %v", err)
	}
	return true
}

// clientIP trusts the last hop of X-Forwarded-For, which is the one our own
// reverse proxy wrote; earlier entries are whatever the caller claimed.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
