// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

// Wallet-driven vault approvals (the push arm of the vault promote step-up).
//
// The CLI still drives POST /fido2/vault-approval/begin with the owner bearer;
// begin additionally (a) records a pending approval keyed by vault_op so the
// wallet can fetch the WebAuthn options, and (b) pushes the owner's wallet. The
// wallet's "Vault approvals" screen fetches the pending request, shows the
// operation, gates on biometric, signs the assertion with its existing fido2
// credential, and POSTs it to /complete — which stashes the operation-bound
// token for the CLI's existing /token poll to collect. No browser, no system
// passkey: the wallet credential the owner already holds is the approver.

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

// vaultApprovalSummary is the human-facing description of a pending approval,
// shown on the wallet screen and carried (as strings) in the push payload.
type vaultApprovalSummary struct {
	Operation   string `json:"operation"`
	Handle      string `json:"handle"`
	Measurement string `json:"measurement"`
}

// vaultPendingStore holds pending wallet approvals keyed by vault_op: the
// WebAuthn options the wallet needs to sign, plus the owner sub and a summary.
// Entries expire with the underlying challenge (5 min) and are removed on a
// successful /complete.
type vaultPendingStore struct {
	mu      sync.Mutex
	pending map[string]*vaultPendingEntry
}

type vaultPendingEntry struct {
	sub       string
	optionsJS json.RawMessage
	summary   vaultApprovalSummary
	expiresAt time.Time
}

func newVaultPendingStore() *vaultPendingStore {
	s := &vaultPendingStore{pending: make(map[string]*vaultPendingEntry)}
	go func() {
		for {
			time.Sleep(time.Minute)
			s.cleanup()
		}
	}()
	return s
}

func (s *vaultPendingStore) put(vaultOp string, e *vaultPendingEntry) {
	s.mu.Lock()
	s.pending[vaultOp] = e
	s.mu.Unlock()
}

func (s *vaultPendingStore) remove(vaultOp string) {
	s.mu.Lock()
	delete(s.pending, vaultOp)
	s.mu.Unlock()
}

// listFor returns the live pending approvals owned by sub.
func (s *vaultPendingStore) listFor(sub string) []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]map[string]interface{}, 0)
	for vaultOp, e := range s.pending {
		if e.sub != sub || now.After(e.expiresAt) {
			continue
		}
		out = append(out, pendingJSON(vaultOp, e))
	}
	return out
}

// get returns the live pending approval for vaultOp, if any.
func (s *vaultPendingStore) get(vaultOp string) (*vaultPendingEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.pending[vaultOp]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e, true
}

func pendingJSON(vaultOp string, e *vaultPendingEntry) map[string]interface{} {
	return map[string]interface{}{
		"vault_op":   vaultOp,
		"options":    e.optionsJS,
		"summary":    e.summary,
		"expires_at": e.expiresAt.Unix(),
	}
}

func (s *vaultPendingStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.pending {
		if now.After(v.expiresAt) {
			delete(s.pending, k)
		}
	}
}

// recordPendingAndPush stores the pending approval and pushes the owner's wallet
// (best-effort). Called from VaultApprovalBegin. optionsJS is the exact WebAuthn
// options the CLI/browser also receive, so the wallet signs the identical
// challenge.
func (h *Handler) recordPendingAndPush(sub, vaultOp string, optionsJS json.RawMessage, summary vaultApprovalSummary, exp int64) {
	h.vaultPending.put(vaultOp, &vaultPendingEntry{
		sub:       sub,
		optionsJS: optionsJS,
		summary:   summary,
		expiresAt: time.Unix(exp, 0),
	})
	pushToken := h.db.GetPushToken(sub)
	if pushToken == "" {
		return // no registered wallet token; the wallet can still poll /pending
	}
	go sendVaultApprovalPush(pushToken, vaultOp, summary)
}

// sendVaultApprovalPush delivers an Expo push tagged type:"vault-approval" so the
// wallet routes it to the Vault approvals screen. Mirrors the recovery flow's
// sendGuardianPush. Values in data must be strings (Expo constraint).
func sendVaultApprovalPush(pushToken, vaultOp string, summary vaultApprovalSummary) {
	body := ""
	switch summary.Operation {
	case "promote":
		body = "Approve a new enclave measurement for " + shortHandle(summary.Handle)
	case "export":
		body = "Approve exporting a key for " + shortHandle(summary.Handle)
	default:
		body = "A vault operation needs your approval"
	}
	// Data carries only the routing type + the capability (vault_op). The wallet
	// fetches the operation details from /pending?challenge= over TLS, so no
	// operation/identity material transits third-party push infrastructure.
	msg := []map[string]interface{}{{
		"to":    pushToken,
		"sound": "default",
		"title": "Vault approval",
		"body":  body,
		"data": map[string]string{
			"type":     "vault-approval",
			"vault_op": vaultOp,
		},
	}}
	payload, _ := json.Marshal(msg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://exp.host/--/api/v2/push/send", bytes.NewReader(payload))
	if err != nil {
		log.Printf("fido2/vault-approval: build push: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("fido2/vault-approval: push send: %v", err)
		return
	}
	resp.Body.Close()
}

// shortHandle renders the app-id segment of a vault handle for a push body.
func shortHandle(handle string) string {
	parts := strings.Split(handle, "/")
	if len(parts) >= 2 {
		id := parts[1]
		if len(id) > 8 {
			return "app " + id[:8]
		}
		return "app " + id
	}
	return "your app"
}

// VaultApprovalPending handles GET /fido2/vault-approval/pending.
//
// Two access modes:
//
//   - ?challenge=<vault_op>: capability-based single fetch, no bearer. The
//     vault_op is a 256-bit, short-TTL, single-use value delivered only via the
//     owner-authenticated /begin (and its push); possessing it authorises
//     VIEWING this one request. Approval still requires the WebAuthn assertion
//     on /complete. This is how the wallet fetches the request: the wallet's
//     identity for the platform RP is pairwise and unlinkable server-side (by
//     design — the pairwise map lives only on the device), so no wallet bearer
//     could list an owner's pendings.
//
//   - no challenge: owner-bearer list (the CLI/browser diagnostics path).
func (h *Handler) VaultApprovalPending(iss *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if vaultOp := r.URL.Query().Get("challenge"); vaultOp != "" {
			e, ok := h.vaultPending.get(vaultOp)
			if !ok {
				errorJSON(w, http.StatusNotFound, "no pending approval for this challenge")
				return
			}
			writeJSON(w, map[string]interface{}{"pending": []map[string]interface{}{pendingJSON(vaultOp, e)}})
			return
		}
		sub, err := h.resolveSubject(r, iss)
		if err != nil {
			errorJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeJSON(w, map[string]interface{}{"pending": h.vaultPending.listFor(sub)})
	}
}

// resolveSubject resolves the caller's sub from either an owner OIDC access
// token or a wallet session token (Bearer wallet:<token>), so wallet-facing
// endpoints work with the only bearer the wallet holds.
func (h *Handler) resolveSubject(r *http.Request, iss *tokens.Issuer) (string, error) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if strings.HasPrefix(raw, "wallet:") {
		if sub, ok := h.walletSessions.Resolve(strings.TrimPrefix(raw, "wallet:")); ok {
			return sub, nil
		}
		return "", errWalletSession
	}
	return bearerSubject(r, iss)
}

var errWalletSession = &sessionError{"invalid or expired wallet session"}

type sessionError struct{ msg string }

func (e *sessionError) Error() string { return e.msg }
