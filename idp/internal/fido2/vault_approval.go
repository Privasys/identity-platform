// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

// Enclave Vault promote step-up (policies-plan.md §9).
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Privasys/idp/internal/tokens"
)

// vaultApprovalDomain MUST match the vault (enclave-os-vault/src/policy.rs) and
// every client. See policies-plan.md §9.
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
			Handle            string `json:"handle"`
			MeasurementDigest string `json:"measurement_digest"`
			PolicyVersion     uint64 `json:"policy_version"`
			TTLSeconds        int64  `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
			req.Handle == "" || req.MeasurementDigest == "" {
			errorJSON(w, http.StatusBadRequest, "handle and measurement_digest required")
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
