// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package wia

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

// WalletSessionResolver resolves an opaque `wallet:<token>` bearer to a user id
// (the fido2 handler's resolver). Enrolment is gated to a signed-in wallet
// session; the user id is used only for that gate — it is never placed in the
// WIA, which identifies a wallet INSTANCE, not an account (§3.3).
type WalletSessionResolver func(token string) (string, bool)

const (
	challengeTTL = 5 * time.Minute
	defaultWIATTL = 48 * time.Hour
	maxBody      = 1 << 16
)

// Handler serves the WIA challenge + enrolment endpoints and issues WIAs with
// the wallet-provider signing key.
type Handler struct {
	issuer   *tokens.Issuer // wallet-provider issuer (distinct from the OIDC issuer)
	resolve  WalletSessionResolver
	policy   AttestPolicy
	ttl      time.Duration
	ch       *challengeStore
}

// Config configures the WIA handler.
type Config struct {
	Issuer   *tokens.Issuer
	Resolver WalletSessionResolver
	Policy   AttestPolicy
	TTL      time.Duration
}

// New creates a WIA handler.
func New(cfg Config) *Handler {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultWIATTL
	}
	return &Handler{
		issuer:  cfg.Issuer,
		resolve: cfg.Resolver,
		policy:  cfg.Policy,
		ttl:     ttl,
		ch:      newChallengeStore(),
	}
}

// ── challenge store (in-memory, single-use, TTL) ──────────────────────────

type challengeStore struct {
	mu sync.Mutex
	m  map[string]time.Time // challenge (b64url) → expiry
}

func newChallengeStore() *challengeStore {
	return &challengeStore{m: make(map[string]time.Time)}
}

func (s *challengeStore) issue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	c := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	// Opportunistic sweep so the map cannot grow unbounded.
	now := time.Now()
	for k, exp := range s.m {
		if now.After(exp) {
			delete(s.m, k)
		}
	}
	s.m[c] = now.Add(challengeTTL)
	s.mu.Unlock()
	return c, nil
}

// consume returns true and removes the challenge if it exists and is unexpired.
func (s *challengeStore) consume(c string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[c]
	if !ok {
		return false
	}
	delete(s.m, c)
	return time.Now().Before(exp)
}

// ── auth ──────────────────────────────────────────────────────────────────

// authWallet requires a valid `Authorization: Bearer wallet:<token>` and
// returns the resolved user id.
func (h *Handler) authWallet(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const p = "Bearer wallet:"
	if !strings.HasPrefix(auth, p) || h.resolve == nil {
		return "", false
	}
	return h.resolve(strings.TrimPrefix(auth, p))
}

// ── endpoints ─────────────────────────────────────────────────────────────

// HandleChallenge (POST /wia/challenge) returns a fresh, single-use enrolment
// challenge the wallet binds into both the device attestation and the holder
// proof-of-possession.
func (h *Handler) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authWallet(r); !ok {
		writeErr(w, http.StatusUnauthorized, "a wallet session is required")
		return
	}
	c, err := h.ch.issue()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge":  c,
		"expires_in": int(challengeTTL.Seconds()),
	})
}

type enrolRequest struct {
	Platform      string      `json:"platform"`   // ios | android
	HolderPub     string      `json:"holder_pub"` // base64url SEC1 uncompressed P-256
	Challenge     string      `json:"challenge"`  // the /wia/challenge value (base64url)
	HolderSig     string      `json:"holder_sig"` // base64url ECDSA(DER) over the challenge
	Attestation   Attestation `json:"attestation"`
	WalletVersion string      `json:"wallet_version"`
}

type enrolResponse struct {
	WIA       string `json:"wia"`
	ExpiresAt int64  `json:"expires_at"`
	Level     string `json:"level"`
}

// HandleEnrol (POST /wia/enrol) validates the device attestation + holder
// proof-of-possession and issues a WIA bound to the holder key.
func (h *Handler) HandleEnrol(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authWallet(r); !ok {
		writeErr(w, http.StatusUnauthorized, "a wallet session is required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "failed to read body")
		return
	}
	var req enrolRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Platform != "ios" && req.Platform != "android" {
		writeErr(w, http.StatusBadRequest, "platform must be 'ios' or 'android'")
		return
	}

	// Fresh, single-use challenge (anti-replay).
	if req.Challenge == "" || !h.ch.consume(req.Challenge) {
		writeErr(w, http.StatusBadRequest, "unknown or expired challenge")
		return
	}
	challengeBytes, err := base64.RawURLEncoding.DecodeString(req.Challenge)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "malformed challenge")
		return
	}

	holderPub, holderRaw, err := parseHolderPub(req.HolderPub)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Proof of possession of the holder key over the fresh challenge.
	sig, err := decodeB64Any(req.HolderSig)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "malformed holder_sig")
		return
	}
	if err := verifyHolderPoP(holderPub, challengeBytes, sig); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}

	// Device attestation: genuine hardware + genuine app, bound to this holder key.
	level, err := ValidateDevice(req.Platform, req.Attestation, challengeBytes, holderRaw, holderPub, h.policy)
	if err != nil {
		writeErr(w, http.StatusForbidden, "device attestation rejected: "+err.Error())
		return
	}

	exp := time.Now().Add(h.ttl)
	jwtStr, err := h.issuer.IssueWIA(tokens.WIAClaims{
		HolderJWK:     tokens.ECPublicJWK(holderPub),
		Level:         level,
		Platform:      req.Platform,
		WalletVersion: req.WalletVersion,
		TTL:           h.ttl,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to issue WIA")
		return
	}
	writeJSON(w, http.StatusOK, enrolResponse{WIA: jwtStr, ExpiresAt: exp.Unix(), Level: level})
}

// HandleJWKS serves the wallet-provider signing key so verifiers can be
// provisioned with it (via /configure) and relying parties can pin it.
func (h *Handler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	h.issuer.HandleJWKS(w, r)
}

// ── small helpers ─────────────────────────────────────────────────────────

func decodeB64Any(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
