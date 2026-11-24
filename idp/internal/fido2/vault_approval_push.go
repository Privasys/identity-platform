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
	"context"
	"encoding/json"
	"github.com/Privasys/idp/internal/push"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/tokens"
	"github.com/Privasys/idp/internal/vaultbinding"
)

// vaultApprovalSummary is the human-facing description of a pending approval,
// shown on the wallet screen and carried (as strings) in the push payload.
//
// The first three fields plus PolicyVersion are the OPERATION the wallet is
// approving; the vault re-derives and enforces the binding from
// (handle, measurement, policy_version, nonce, exp), so these are the
// authoritative anchor. The remaining fields are DISPLAY CONTEXT the initiator
// (the owner's CLI) supplied to help a human recognise the operation — they are
// NOT bound into vault_op and must be read as advisory hints, never as the
// security decision (the measurement digest is the truth). See
// attribute-billing / vault promote-step-up design.
type vaultApprovalSummary struct {
	Operation     string `json:"operation"`
	Handle        string `json:"handle"`
	Measurement   string `json:"measurement"`
	PolicyVersion uint64 `json:"policy_version,omitempty"`

	// Advisory context (initiator-supplied; not cryptographically bound).
	AppName string `json:"app_name,omitempty"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
	KeyType string `json:"key_type,omitempty"`
	Summary string `json:"summary,omitempty"`

	// Identifiers the wallet uses to fetch mgmt release provenance (the
	// published release + old→new code diff) itself. Not display text.
	AppID     string `json:"app_id,omitempty"`
	VersionID string `json:"version_id,omitempty"`

	// Reshare only: the inputs of the resharing context the wallet recomputes
	// measurement_digest from (target vault build, new vaults in index order,
	// new threshold, dealing helpers, the unchanged public key). Advisory like
	// the rest; the recomputation is what makes them count.
	TargetMrenclave string `json:"target_mrenclave,omitempty"`
	TargetVaults    string `json:"target_vaults,omitempty"`
	Threshold       string `json:"threshold,omitempty"`
	Helpers         string `json:"helpers,omitempty"`
	PublicKey       string `json:"public_key,omitempty"`

	// A v1 approval says what it binds beside the fields above (its nonce and
	// expiry), so the wallet recomputes the challenge from what it shows.
	Nonce string `json:"nonce,omitempty"`
	Exp   int64  `json:"exp,omitempty"`

	// Binding v2 only: every field of the text the approval binds, so the
	// wallet rebuilds it; the vaults' own identities, which the wallet
	// verifies before it shows the constellation; and, for update_policy, the
	// new policy, whose digest is the target. Served with the pending
	// approval, never carried in a push.
	Binding          *vaultBindingFields          `json:"binding,omitempty"`
	MemberIdentities []vaultbinding.VaultIdentity `json:"member_identities,omitempty"`
	NewPolicy        json.RawMessage              `json:"new_policy,omitempty"`
	// A delete_after for a created successor: the key the old one waits for.
	// The wallet recomputes the binding's target from it.
	SuccessorHandle string `json:"successor_handle,omitempty"`
	// The vaults' release tag, a hint for the wallet's lookup. Bound by
	// nothing; the wallet verifies the release on GitHub itself.
	VaultRelease string `json:"vault_release,omitempty"`
}

// vaultReleaseTag is the only shape a vault release hint may have.
var vaultReleaseTag = regexp.MustCompile(`^vault-v\d{1,4}\.\d{1,4}\.\d{1,4}$`)

// withVaultRelease passes on the vaults' release tag as a hint for the
// wallet's lookup. Anything that is not a release tag is dropped.
func (s vaultApprovalSummary) withVaultRelease(tag string) vaultApprovalSummary {
	if vaultReleaseTag.MatchString(tag) {
		s.VaultRelease = tag
	}
	return s
}

// withSuccessor names the created successor of a delete_after.
func (s vaultApprovalSummary) withSuccessor(v2 bool, successor string) vaultApprovalSummary {
	if v2 {
		s.SuccessorHandle = successor
	}
	return s
}

// withBindingV2 adds what a v2 approval carries for the wallet. A v1 summary
// (b nil) is unchanged.
func (s vaultApprovalSummary) withBindingV2(b *vaultBindingFields, ids []vaultbinding.VaultIdentity, newPolicy json.RawMessage) vaultApprovalSummary {
	if b == nil {
		return s
	}
	s.Binding, s.MemberIdentities = b, ids
	if len(newPolicy) > 0 && string(newPolicy) != "null" {
		s.NewPolicy = newPolicy
	}
	return s
}

// withV1Binding adds what a v1 approval binds beside its shown fields. A v2
// summary carries its whole binding instead.
func (s vaultApprovalSummary) withV1Binding(v2 bool, nonce string, exp int64) vaultApprovalSummary {
	if !v2 {
		s.Nonce, s.Exp = nonce, exp
	}
	return s
}

// maxReshareFieldBytes bounds one reshare context field. Never clipped: a
// clipped value could not recompute the digest, so a longer one is refused.
const maxReshareFieldBytes = 4096

func reshareContextFits(fields ...string) bool {
	for _, f := range fields {
		if len(f) > maxReshareFieldBytes {
			return false
		}
	}
	return true
}

// withReshare carries the resharing-context inputs on a reshare approval and
// drops them on any other operation.
func (s vaultApprovalSummary) withReshare(op, mrenclave, vaults, threshold, helpers, publicKey string) vaultApprovalSummary {
	if op != "reshare" {
		return s
	}
	s.TargetMrenclave, s.TargetVaults, s.Threshold, s.Helpers, s.PublicKey = mrenclave, vaults, threshold, helpers, publicKey
	return s
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
// It reports whether a wallet push token is registered for the subject, so the
// caller can tell the initiator that no push is coming instead of leaving them
// waiting on a notification that will never arrive.
func (h *Handler) recordPendingAndPush(sub, vaultOp string, optionsJS json.RawMessage, summary vaultApprovalSummary, exp int64) (pushRegistered bool) {
	h.vaultPending.put(vaultOp, &vaultPendingEntry{
		sub:       sub,
		optionsJS: optionsJS,
		summary:   summary,
		expiresAt: time.Unix(exp, 0),
	})
	pushTokens := h.db.GetPushTokens(sub)
	if len(pushTokens) == 0 {
		// No registered wallet token. The approval is still pending and the
		// wallet can find it via /pending, but nothing will nudge it — an
		// operator watching only the log used to see silence here.
		log.Printf("fido2: vault-approval %s… has NO push token for %s; the wallet must open Vault approvals itself", vaultOp[:12], sub)
		return false
	}
	for _, pushToken := range pushTokens {
		go h.sendVaultApprovalPush(sub, pushToken, vaultOp, summary)
	}
	return true
}

// sendVaultApprovalPush delivers an Expo push tagged type:"vault-approval" so the
// wallet routes it to the Vault approvals screen. Mirrors the recovery flow's
// sendGuardianPush. Values in data must be strings (Expo constraint).
func (h *Handler) sendVaultApprovalPush(userID, pushToken, vaultOp string, summary vaultApprovalSummary) {
	// Prefer the friendly app name in the push body when the initiator supplied
	// it; fall back to the truncated handle.
	who := summary.AppName
	if who == "" {
		who = shortHandle(summary.Handle)
	}
	body := ""
	switch summary.Operation {
	case "promote":
		body = "Approve a new version for " + who
		if summary.Version != "" {
			body += " (" + summary.Version + ")"
		}
	case "export":
		body = "Approve exporting a key for " + who
	case "policy-update":
		body = "Approve a key-policy update for " + who
	case "reshare":
		body = "Approve moving a key to new vaults for " + who
	default:
		body = "A vault operation needs your approval"
	}
	// Data carries only the routing type + the capability (vault_op). The wallet
	// fetches the operation details from /pending?challenge= over TLS, so no
	// operation/identity material transits third-party push infrastructure.
	if err := push.Notify(context.Background(), h.db, userID, push.Message{
		Token: pushToken,
		Title: "Vault approval",
		Body:  body,
		// Only the routing type and the capability. The wallet fetches the
		// operation details from /pending?challenge= over TLS, so no operation
		// or identity material transits third-party push infrastructure.
		Data: map[string]string{
			"type":     "vault-approval",
			"vault_op": vaultOp,
		},
	}); err != nil {
		log.Printf("fido2/vault-approval: push send: %v", err)
	}
}

// shortHandle names a vault handle for a push body when the initiator gave no
// name. The push travels through third-party push infrastructure, so it uses
// only the owner-given key name, never the key vault's id or a user's subject:
// vaults/<keyvault-id>/<name>[/v<N>] is "key <name>", users/<sub>/<name> is
// "secret <name>", and an app's handle is "app <id prefix>".
func shortHandle(handle string) string {
	parts := strings.Split(handle, "/")
	if len(parts) >= 3 && parts[2] != "" {
		switch parts[0] {
		case "vaults":
			return "key " + clipName(parts[2])
		case "users":
			return "secret " + clipName(parts[2])
		}
	}
	if parts[0] == "vaults" || parts[0] == "users" {
		return "your key"
	}
	if len(parts) >= 2 {
		id := parts[1]
		if len(id) > 8 {
			return "app " + id[:8]
		}
		return "app " + id
	}
	return "your app"
}

// maxPushNameRunes bounds a key name in a push body.
const maxPushNameRunes = 48

func clipName(s string) string {
	if r := []rune(s); len(r) > maxPushNameRunes {
		return string(r[:maxPushNameRunes-1]) + "…"
	}
	return s
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

// walletDeepLink is the link that takes the Privasys Wallet straight to a
// pending vault approval. It is the same destination the push notification
// routes to (the wallet's /vault-approvals route, which reads vault_op), so a
// QR of this link is a push-free way to hand the approval from a desktop to the
// phone that holds the credential.
//
// The scheme must match the wallet's registered one (app.config.ts): the
// production build is `privasys-wallet` — NOT `privasys`, which opens nothing.
// Dev/preview builds register privasys-wallet-dev / -preview, so a QR made here
// targets a production wallet.
func walletDeepLink(vaultOp string) string {
	return "privasys-wallet://vault-approvals?vault_op=" + url.QueryEscape(vaultOp)
}

// maxSummaryRunes bounds the plain-language summary an initiator attaches to
// an approval: a few lines on a phone card, never a document.
const maxSummaryRunes = 600

// clipSummary trims an initiator's summary to what a wallet card can show.
func clipSummary(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxSummaryRunes {
		return string(r[:maxSummaryRunes-1]) + "…"
	}
	return s
}
