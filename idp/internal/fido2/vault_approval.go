// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

// Enclave Vault promote step-up (the vault promote-step-up design).
//
// A vault key's promote rule may carry Condition::OidcStepUp{operation_bound},
// requiring the owner's bearer to additionally prove a fresh WebAuthn assertion
// bound to THIS promote. This grant produces that token:
//
//	POST /fido2/vault-approval/begin     (Bearer owner token; body = the op tuple)
//	    -> WebAuthn CredentialAssertion whose challenge IS the operation binding
//	POST /fido2/vault-approval/complete?challenge=<vault_op>  (the assertion)
//	    -> { access_token } : owner-sub, amr:["webauthn"], vault_op, nonce, exp
//
// The vault recomputes vault_op from (handle, promoted measurement,
// policy_version) + the token's (nonce, exp) and checks it, so a stolen bearer
// plus a captured approval cannot promote a different/forged measurement.

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Privasys/idp/internal/tokens"
)

// vaultApprovalPage is the browser ceremony page the CLI opens: it reads the
// WebAuthn options the CLI passed in the URL fragment, runs
// navigator.credentials.get() against the owner's passkey, and POSTs the
// assertion to /fido2/vault-approval/complete. Served same-origin so the
// assertion validates against the IdP RP ID. See stepup_browser.go in the CLI.
//
//go:embed vault_approval.html
var vaultApprovalPage []byte

// VaultApprovalPage serves GET /fido2/vault-approval (the ceremony page).
func (h *Handler) VaultApprovalPage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(vaultApprovalPage)
	}
}

// vaultResultStore briefly holds the operation-bound token issued by
// VaultApprovalComplete, keyed by vault_op, so the CLI (which drove /begin but
// not /complete, since the browser did) can collect it by polling. The token is
// owner-scoped (only the matching sub may fetch it) and single-use.
type vaultResultStore struct {
	mu      sync.Mutex
	results map[string]vaultResultEntry
}

type vaultResultEntry struct {
	sub       string
	token     string
	expiresAt time.Time
}

func newVaultResultStore() *vaultResultStore {
	s := &vaultResultStore{results: make(map[string]vaultResultEntry)}
	go func() {
		for {
			time.Sleep(time.Minute)
			s.cleanup()
		}
	}()
	return s
}

func (s *vaultResultStore) put(vaultOp, sub, token string, exp int64) {
	s.mu.Lock()
	s.results[vaultOp] = vaultResultEntry{sub: sub, token: token, expiresAt: time.Unix(exp, 0)}
	s.mu.Unlock()
}

// take returns the stashed token for vaultOp iff it exists, has not expired, and
// belongs to sub. It is single-use: a hit is deleted. The bool reports whether a
// (live, sub-matching) entry was found.
func (s *vaultResultStore) take(vaultOp, sub string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.results[vaultOp]
	if !ok || time.Now().After(e.expiresAt) || e.sub != sub {
		return "", false
	}
	delete(s.results, vaultOp)
	return e.token, true
}

func (s *vaultResultStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.results {
		if now.After(v.expiresAt) {
			delete(s.results, k)
		}
	}
}

// VaultApprovalToken handles GET /fido2/vault-approval/token?challenge=<vault_op>.
//
// Auth: Authorization: Bearer <owner access token> (the same owner that drove
// /begin). Returns { access_token, expires_at } once the browser has completed
// the ceremony and the token was stashed; 202 while still pending. Single-use.
func (h *Handler) VaultApprovalToken(iss *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub, err := bearerSubject(r, iss)
		if err != nil {
			errorJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		vaultOp := r.URL.Query().Get("challenge")
		if vaultOp == "" {
			errorJSON(w, http.StatusBadRequest, "challenge required")
			return
		}
		tok, ok := h.vaultResults.take(vaultOp, sub)
		if !ok {
			// Not yet completed (or expired / not this owner's): tell the CLI to
			// keep polling.
			w.WriteHeader(http.StatusAccepted)
			writeJSON(w, map[string]string{"status": "pending"})
			return
		}
		writeJSON(w, map[string]string{"access_token": tok})
	}
}

// vaultApprovalDomain MUST match the vault (enclave-os-vault/src/policy.rs) and
// every client. See the vault promote-step-up design.
const vaultApprovalDomain = "privasys-vault-approval/v1"

// computeVaultApprovalBinding hashes the canonical newline-joined operation
// tuple. Inputs are rendered as UTF-8 strings so the digest is identical to the
// vault's `vault_op_binding` (Rust) and any TS/Go client.
func computeVaultApprovalBinding(handle, measurementHex string, policyVersion uint64, nonce string, exp int64) [32]byte {
	input := fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%d",
		vaultApprovalDomain, handle, measurementHex, policyVersion, nonce, exp)
	return sha256.Sum256([]byte(input))
}

// VaultApprovalBegin handles POST /fido2/vault-approval/begin.
//
// Auth: Authorization: Bearer <owner access token>. Body:
//
//	{"handle":"...", "measurement_digest":"<hex>", "policy_version":N, "ttl_seconds":120}
//
// Returns the standard WebAuthn CredentialAssertion; its challenge IS the
// operation binding, so a verified assertion proves approval of this exact op.
func (h *Handler) VaultApprovalBegin(iss *tokens.Issuer, audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub, err := bearerSubject(r, iss)
		if err != nil {
			errorJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		var req struct {
			// Operation discriminates the bound op. "promote" (default) binds
			// the promoted profile's measurement; "export" has no target
			// measurement and binds the empty measurement slot, matching the
			// vault's handle_export OpBinding.
			Operation         string `json:"operation"`
			Handle            string `json:"handle"`
			MeasurementDigest string `json:"measurement_digest"`
			PolicyVersion     uint64 `json:"policy_version"`
			TTLSeconds        int64  `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Handle == "" {
			errorJSON(w, http.StatusBadRequest, "handle required")
			return
		}
		switch req.Operation {
		case "export":
			// Export binds the empty measurement slot; a measurement_digest is
			// neither required nor honoured (force it empty so a caller cannot
			// smuggle a non-empty binding that would collide with promote).
			req.MeasurementDigest = ""
		case "", "promote":
			req.Operation = "promote"
			if req.MeasurementDigest == "" {
				errorJSON(w, http.StatusBadRequest, "measurement_digest required for promote")
				return
			}
		default:
			errorJSON(w, http.StatusBadRequest, "unknown operation")
			return
		}
		ttl := req.TTLSeconds
		if ttl <= 0 || ttl > 300 {
			ttl = 120
		}
		now := time.Now().Unix()
		exp := now + ttl

		nb := make([]byte, 16)
		if _, err := rand.Read(nb); err != nil {
			errorJSON(w, http.StatusInternalServerError, "nonce generation failed")
			return
		}
		nonce := base64.RawURLEncoding.EncodeToString(nb)

		binding := computeVaultApprovalBinding(req.Handle, req.MeasurementDigest, req.PolicyVersion, nonce, exp)
		vaultOp := base64.RawURLEncoding.EncodeToString(binding[:])

		creds, err := h.loadCredentials(sub)
		if err != nil || len(creds) == 0 {
			errorJSON(w, http.StatusNotFound, "no credentials for user")
			return
		}
		user := &idpUser{ID: []byte(sub), Name: sub, Credentials: creds}

		options, sessionData, err := h.webAuthn.BeginLogin(user)
		if err != nil {
			log.Printf("fido2/vault-approval/begin: %v", err)
			errorJSON(w, http.StatusInternalServerError, "begin failed")
			return
		}
		// Override the random challenge with the operation binding.
		options.Response.Challenge = protocol.URLEncodedBase64(binding[:])
		sessionData.Challenge = vaultOp

		h.challenges.put(vaultOp, &challengeEntry{
			sessionData: sessionData,
			user:        user,
			expiresAt:   time.Now().Add(5 * time.Minute),
			vaultApproval: &vaultApprovalMeta{
				sub:     sub,
				vaultOp: vaultOp,
				nonce:   nonce,
				iat:     now,
				exp:     exp,
			},
		})
		// Record the pending approval + push the owner's wallet, so the ceremony
		// can also be completed from the Privasys Wallet (its fido2 credential is
		// not a system passkey a browser can reach). The wallet fetches these exact
		// options from /pending and posts the assertion to /complete.
		optionsJS, _ := json.Marshal(options)
		h.recordPendingAndPush(sub, vaultOp, optionsJS, vaultApprovalSummary{
			Operation:   req.Operation,
			Handle:      req.Handle,
			Measurement: req.MeasurementDigest,
		}, exp)
		writeJSON(w, options)
	}
}

// VaultApprovalComplete handles POST /fido2/vault-approval/complete?challenge=<vault_op>.
//
// Body: a standard WebAuthn AuthenticatorAssertionResponse. On success returns
// the operation-bound access token.
func (h *Handler) VaultApprovalComplete(iss *tokens.Issuer, audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("challenge")
		entry, ok := h.challenges.pop(challenge)
		if !ok || entry.vaultApproval == nil {
			errorJSON(w, http.StatusBadRequest, "challenge expired or not found")
			return
		}
		if _, err := h.webAuthn.FinishLogin(entry.user, *entry.sessionData, r); err != nil {
			log.Printf("fido2/vault-approval/complete: %v", err)
			errorJSON(w, http.StatusBadRequest, fmt.Sprintf("verification failed: %s", err))
			return
		}
		m := entry.vaultApproval
		tok, err := iss.IssueVaultApprovalToken(m.sub, audience, m.vaultOp, m.nonce, m.iat, m.exp)
		if err != nil {
			log.Printf("fido2/vault-approval/complete: issue: %v", err)
			errorJSON(w, http.StatusInternalServerError, "token issuance failed")
			return
		}
		// Stash for browser-driven flows: when the ceremony ran in a browser page
		// (the CLI drove /begin but the page did /complete), the CLI collects the
		// token by polling GET /fido2/vault-approval/token. Owner-scoped + single-
		// use. Direct callers (e2e software authenticator) still read the response.
		h.vaultResults.put(m.vaultOp, m.sub, tok, m.exp)
		h.vaultPending.remove(m.vaultOp)
		log.Printf("fido2: vault-approval issued for %s (vault_op %s…)", m.sub, m.vaultOp[:12])
		writeJSON(w, map[string]interface{}{"access_token": tok, "expires_at": m.exp})
	}
}

// bearerSubject verifies an `Authorization: Bearer` access token (signed by this
// IdP) and returns its `sub`.
func bearerSubject(r *http.Request, iss *tokens.Issuer) (string, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", fmt.Errorf("missing bearer token")
	}
	claims, err := iss.VerifyAccessToken(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		return "", err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("token has no sub")
	}
	return sub, nil
}
