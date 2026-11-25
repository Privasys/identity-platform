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
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Privasys/idp/internal/push"
	"github.com/Privasys/idp/internal/tokens"
	"github.com/Privasys/idp/internal/vaultbinding"
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
	// outcomes remembers how each approval ended, for the approval page,
	// after the initiator has collected the token (a take is single-use).
	// It holds no token: only approved or declined.
	outcomes map[string]vaultOutcome
}

type vaultOutcome struct {
	declined  bool
	expiresAt time.Time
}

type vaultResultEntry struct {
	sub       string
	token     string
	declined  bool // the owner declined on the phone: no token will come
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
	s.recordOutcome(vaultOp, false, time.Unix(exp, 0))
	s.mu.Unlock()
}

// recordOutcome notes how vaultOp ended. Callers hold s.mu.
func (s *vaultResultStore) recordOutcome(vaultOp string, declined bool, expiresAt time.Time) {
	if s.outcomes == nil {
		s.outcomes = make(map[string]vaultOutcome)
	}
	s.outcomes[vaultOp] = vaultOutcome{declined: declined, expiresAt: expiresAt}
}

// outcome reports how vaultOp ended: "approved", "declined", or "" when it
// has not ended or is no longer known.
func (s *vaultResultStore) outcome(vaultOp string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.outcomes[vaultOp]
	if !ok || time.Now().After(o.expiresAt) {
		return ""
	}
	if o.declined {
		return "declined"
	}
	return "approved"
}

// decline records that the owner refused vaultOp, so the initiator's poll ends.
func (s *vaultResultStore) decline(vaultOp, sub string, expiresAt time.Time) {
	s.mu.Lock()
	s.results[vaultOp] = vaultResultEntry{sub: sub, declined: true, expiresAt: expiresAt}
	s.recordOutcome(vaultOp, true, expiresAt)
	s.mu.Unlock()
}

// take returns the stashed result for vaultOp iff it exists, has not expired,
// and belongs to sub: a token, or a refusal. It is single-use: a hit is
// deleted. The bool reports whether a (live, sub-matching) entry was found.
func (s *vaultResultStore) take(vaultOp, sub string) (vaultResultEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.results[vaultOp]
	if !ok || time.Now().After(e.expiresAt) || e.sub != sub {
		return vaultResultEntry{}, false
	}
	delete(s.results, vaultOp)
	return e, true
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
	for k, v := range s.outcomes {
		if now.After(v.expiresAt) {
			delete(s.outcomes, k)
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
		res, ok := h.vaultResults.take(vaultOp, sub)
		if !ok {
			// Not yet completed (or expired / not this owner's): tell the CLI to
			// keep polling.
			w.WriteHeader(http.StatusAccepted)
			writeJSON(w, map[string]string{"status": "pending"})
			return
		}
		if res.declined {
			writeDeclined(w)
			return
		}
		writeJSON(w, map[string]string{"access_token": res.token})
	}
}

// VaultApprovalStatus handles GET /fido2/vault-approval/status?challenge=<vault_op>.
//
// Where one approval stands, for the approval page: "pending" while it waits,
// "approved" or "declined" once answered (whether in the wallet or with a
// passkey on the page), "gone" when it expired or was never known. As for GET
// pending, the challenge is the capability; this tells its holder only the
// outcome, never a token.
func (h *Handler) VaultApprovalStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vaultOp := r.URL.Query().Get("challenge")
		if vaultOp == "" {
			errorJSON(w, http.StatusBadRequest, "challenge required")
			return
		}
		status := "gone"
		if _, ok := h.vaultPending.get(vaultOp); ok {
			status = "pending"
		} else if o := h.vaultResults.outcome(vaultOp); o != "" {
			status = o
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]string{"status": status})
	}
}

// vaultApprovalDomain MUST match the vault (enclave-os-vault/src/policy.rs) and
// every client. See the vault promote-step-up design.
const vaultApprovalDomain = "privasys-vault-approval/v1"

// vaultApprovalMaxTTL bounds how long a pending approval (and the token it
// yields) stays live. Long enough for a human to reach their phone, short
// enough that an unnoticed request cannot linger.
const vaultApprovalMaxTTL = int64(300)

// computeVaultApprovalBinding hashes the canonical newline-joined operation
// tuple. Inputs are rendered as UTF-8 strings so the digest is identical to the
// vault's `vault_op_binding` (Rust) and any TS/Go client.
func computeVaultApprovalBinding(handle, measurementHex string, policyVersion uint64, nonce string, exp int64) [32]byte {
	input := fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%d",
		vaultApprovalDomain, handle, measurementHex, policyVersion, nonce, exp)
	return sha256.Sum256([]byte(input))
}

// vaultPolicyUpdateSlot is what a v1 "policy-update" approval binds in the
// measurement slot: its own name, so that it cannot stand for an export (the
// empty slot) or a promote (a digest).
const vaultPolicyUpdateSlot = "policy-update"

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
			Operation string `json:"operation"`
			// Audience is the aud of the token this approval yields: the
			// audience the target vaults accept (one of the platform
			// audiences). Empty = the default audience.
			Audience          string `json:"audience"`
			Handle            string `json:"handle"`
			MeasurementDigest string `json:"measurement_digest"`
			PolicyVersion     uint64 `json:"policy_version"`
			TTLSeconds        int64  `json:"ttl_seconds"`
			// Binding v2 (vault_approval_v2.go), switched on by
			// binding_version 2: the approval names the vaults it is for and
			// binds its target, which replaces measurement_digest.
			BindingVersion   int                          `json:"binding_version"`
			Target           string                       `json:"target"`
			Members          []string                     `json:"members"`
			MemberIdentities []vaultbinding.VaultIdentity `json:"member_identities"`
			IssuerIndex      uint32                       `json:"issuer_index"`
			NewPolicy        json.RawMessage              `json:"new_policy"`
			// update_policy_from only: the policy being replaced, as the
			// vault's GetPolicy returns it.
			CurrentPolicy json.RawMessage `json:"current_policy"`
			// delete_after only: the created successor the old key waits for.
			SuccessorHandle string `json:"successor_handle"`
			// Advisory display context for the approver's wallet. Not part of the
			// vault_op binding — the vault enforces only the operation tuple.
			Context struct {
				AppName string `json:"app_name"`
				Version string `json:"version"`
				Source  string `json:"source"`
				KeyType string `json:"key_type"`
				// Summary says in plain words what the operation does, e.g.
				// the callers an app policy admits, so a widened list is
				// visible before the approver taps. Display only, like the rest.
				Summary string `json:"summary"`
				// Identifiers the wallet uses to fetch release provenance
				// (published release + code-diff) from mgmt itself.
				AppID     string `json:"app_id"`
				VersionID string `json:"version_id"`
				// VaultRelease is the vaults' release tag (e.g.
				// "vault-v0.41.0"), a hint for the wallet's own lookup. The
				// wallet verifies that release itself.
				VaultRelease string `json:"vault_release"`
				// Reshare only: the inputs of the resharing context, so the
				// wallet can recompute measurement_digest and show the target
				// vault build as its published release. Display only: a value
				// that does not match the digest fails the wallet's check.
				TargetMrenclave string `json:"target_mrenclave"`
				TargetVaults    string `json:"target_vaults"`
				Threshold       string `json:"threshold"`
				Helpers         string `json:"helpers"`
				PublicKey       string `json:"public_key"`
			} `json:"context"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Handle == "" {
			errorJSON(w, http.StatusBadRequest, "handle required")
			return
		}
		aud, err := vaultApprovalAudience(req.Audience, audience)
		if err != nil {
			errorJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.BindingVersion != 0 && req.BindingVersion != 1 && req.BindingVersion != 2 {
			errorJSON(w, http.StatusBadRequest, "unknown binding_version")
			return
		}
		v2 := req.BindingVersion == 2
		v2Fields := vaultV2Fields{
			Operation: req.Operation, Handle: req.Handle, Target: req.Target, PolicyVersion: req.PolicyVersion,
			Members: req.Members, IssuerIndex: req.IssuerIndex, NewPolicy: req.NewPolicy,
			SuccessorHandle: req.SuccessorHandle, CurrentPolicy: req.CurrentPolicy,
		}
		deleteAfter := req.BindingVersion == 2 && req.Operation == string(vaultbinding.BindDeleteAfter)
		if deleteAfter {
			v2Fields.TTLSeconds = req.TTLSeconds
		}
		var v2Target string
		if v2 {
			if v2Target, err = checkVaultV2Fields(v2Fields, false); err == nil {
				err = checkVaultMemberIdentities(req.Members, req.MemberIdentities)
			}
			if err != nil {
				errorJSON(w, http.StatusBadRequest, err.Error())
				return
			}
			// What the wallet shows as the bound value.
			req.MeasurementDigest = v2Target
			if req.SuccessorHandle != "" && !deleteAfter {
				errorJSON(w, http.StatusBadRequest, "successor_handle is for delete_after only")
				return
			}
			if c := req.Context; req.Operation == "reshare" &&
				!reshareContextFits(c.TargetMrenclave, c.TargetVaults, c.Threshold, c.Helpers, c.PublicKey) {
				errorJSON(w, http.StatusBadRequest, "reshare context field too long")
				return
			}
		}
		// v1 operations and what each binds. A v2 request was checked above.
		if !v2 {
			switch req.Operation {
			case "export":
				// Export binds the empty measurement slot; a measurement_digest is
				// neither required nor honoured (force it empty so a caller cannot
				// smuggle a non-empty binding that would collide with promote).
				req.MeasurementDigest = ""
			case "policy-update":
				// A key-policy update (vault UpdatePolicy — e.g. arming the
				// acceptable-TCB set, retiring a measurement under step-up). The
				// vault's UpdatePolicy step-up condition is amr-only (non-bound),
				// so the vault reads no binding from this token.
				//
				// The slot is NOT left empty. An empty slot is what "export"
				// binds, so a token issued for a rules change would also be a
				// valid export approval for the same key at the same policy
				// version: a card that says "rules" yielding a token that can
				// export. The slot carries the operation's own name instead,
				// which no other operation binds (promote binds a 64-hex digest,
				// export the empty string), so the token fits nothing else.
				req.MeasurementDigest = vaultPolicyUpdateSlot
			case "reshare":
				// Resharing a threshold key: its old vaults deal their shares to
				// new ones (a renewal, or a move to another constellation). The
				// measurement slot carries the vault's resharing context (the key,
				// the helpers, the new vaults, the threshold and the new vaults'
				// build), so an approval moves the key to exactly those vaults.
				if len(req.MeasurementDigest) != 64 {
					errorJSON(w, http.StatusBadRequest, "measurement_digest (the 32-byte resharing context, hex) required for reshare")
					return
				}
				c := req.Context
				if !reshareContextFits(c.TargetMrenclave, c.TargetVaults, c.Threshold, c.Helpers, c.PublicKey) {
					errorJSON(w, http.StatusBadRequest, "reshare context field too long")
					return
				}
			case "", "promote":
				req.Operation = "promote"
				if req.MeasurementDigest == "" {
					errorJSON(w, http.StatusBadRequest, "measurement_digest required for promote")
					return
				}
			case "app-policy":
				// An app's owner approving its policy document: who owns the app,
				// which peers it may call and who may call it. The runtime
				// recomputes this binding from the document in front of it, as the
				// vault does for promote, so an approval installs one document and
				// no other. handle is "app:<app-id>:policy", measurement_digest
				// the SHA-256 of the document bytes, policy_version its seq.
				if req.MeasurementDigest == "" {
					errorJSON(w, http.StatusBadRequest, "measurement_digest (the policy document digest) required for app-policy")
					return
				}
				if !strings.HasPrefix(req.Handle, "app:") || !strings.HasSuffix(req.Handle, ":policy") {
					errorJSON(w, http.StatusBadRequest, "app-policy handle must be app:<app-id>:policy")
					return
				}
			case "app-recovery":
				// An app-defined recovery approval (e.g. Privasys Drive
				// recover_tenant): the app computes a digest over its recovery
				// tuple and the approver's assertion binds it. handle carries the
				// app-scoped operation URI (e.g. "app:<app-id>:recover:<rid>"),
				// measurement_digest the recovery digest (hex). The verifying app
				// recomputes the binding from its own record plus the token's
				// nonce/exp, exactly as the vault does for promote. Cannot collide
				// with promote/export: the handle namespace is disjoint from vault
				// key handles.
				if req.MeasurementDigest == "" {
					errorJSON(w, http.StatusBadRequest, "measurement_digest (the recovery digest) required for app-recovery")
					return
				}
				if !strings.HasPrefix(req.Handle, "app:") {
					errorJSON(w, http.StatusBadRequest, "app-recovery handle must be an app: URI")
					return
				}
			default:
				errorJSON(w, http.StatusBadRequest, "unknown operation")
				return
			}
		}
		// Clamp, don't collapse: an over-long request used to fall back to
		// the 120s default, so asking for MORE time silently gave you LESS
		// — and the approval expired while the human walked to their phone.
		// Saturate at the maximum instead; only an absent/invalid value
		// takes the default.
		ttl := req.TTLSeconds
		if ttl <= 0 {
			ttl = 120
		}
		if ttl > vaultApprovalMaxTTL {
			ttl = vaultApprovalMaxTTL
		}
		now := time.Now().Unix()
		exp := now + ttl
		// The owner answers within the usual window. A delete_after's token
		// then lives on, to be presented once the migration or rotation has
		// succeeded.
		pendingExp := exp
		if deleteAfter {
			// Only a delete beside a promote waits for anything, and that form
			// is a batch's. Here the successor is created, so it exists: the
			// token may outlive the tap by the ordinary limit, no more.
			if held := req.TTLSeconds; held > ttl && now+held > exp {
				exp = now + held
			}
		}

		nb := make([]byte, 16)
		if _, err := rand.Read(nb); err != nil {
			errorJSON(w, http.StatusInternalServerError, "nonce generation failed")
			return
		}
		nonce := base64.RawURLEncoding.EncodeToString(nb)

		var binding [32]byte
		var vaultOp string
		var v2Binding *vaultBindingFields
		if v2 {
			fields, sum, op, err := bindVaultV2(sub, v2Fields, v2Target, nonce, exp)
			if err != nil {
				errorJSON(w, http.StatusBadRequest, err.Error())
				return
			}
			binding, vaultOp, v2Binding = sum, op, &fields
		} else {
			binding = computeVaultApprovalBinding(req.Handle, req.MeasurementDigest, req.PolicyVersion, nonce, exp)
			vaultOp = base64.RawURLEncoding.EncodeToString(binding[:])
		}

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
				sub:      sub,
				vaultOp:  vaultOp,
				nonce:    nonce,
				iat:      now,
				exp:      exp,
				audience: aud,
				asked: fmt.Sprintf("op %s, handle %q, vault_op %s; asked from %s",
					vaultOpName(req.Operation), logField(req.Handle), vaultOp, vaultRequester(r, iss)),
			},
		})
		// Record the pending approval + push the owner's wallet, so the ceremony
		// can also be completed from the Privasys Wallet (its fido2 credential is
		// not a system passkey a browser can reach). The wallet fetches these exact
		// options from /pending and posts the assertion to /complete.
		optionsJS, _ := json.Marshal(options)
		pushRegistered := h.recordPendingAndPush(sub, vaultOp, optionsJS, vaultApprovalSummary{
			Operation:     req.Operation,
			Handle:        req.Handle,
			Measurement:   req.MeasurementDigest,
			PolicyVersion: req.PolicyVersion,
			AppName:       req.Context.AppName,
			Version:       req.Context.Version,
			Source:        req.Context.Source,
			KeyType:       req.Context.KeyType,
			Summary:       clipSummary(req.Context.Summary),
			AppID:         req.Context.AppID,
			VersionID:     req.Context.VersionID,
		}.withReshare(req.Operation, req.Context.TargetMrenclave, req.Context.TargetVaults,
			req.Context.Threshold, req.Context.Helpers, req.Context.PublicKey).
			withBindingV2(v2Binding, req.MemberIdentities, req.NewPolicy).withCurrentPolicy(v2, req.CurrentPolicy).withV1Binding(v2, nonce, exp).
			withSuccessor(v2, req.SuccessorHandle).withVaultRelease(req.Context.VaultRelease), pendingExp)
		// Log the REQUEST as well as the completion. Only /complete used to
		// log ("vault-approval issued"), which reads like a request being
		// created — so an operator watching the log could not tell an
		// approval that had succeeded from one that never arrived, and
		// mistook successful approvals for failures (2026-08-01).
		// Who asked, and for what, in full: an approval somebody tapped has to
		// be traceable to the session that requested it from this line alone.
		// It was not: with several tools able to ask one owner at once, an
		// approval taken for a different, expected one could only be traced
		// by reading around it (2026-11-25).
		log.Printf("fido2: vault-approval requested by %s (op %s, handle %q, binding %d, aud %s, vault_op %s, ttl %ds, push_registered=%t) from %s",
			sub, vaultOpName(req.Operation), logField(req.Handle), req.BindingVersion, aud, vaultOp, ttl, pushRegistered, vaultRequester(r, iss))
		// Return the WebAuthn options plus how the owner can actually approve.
		// `publicKey` stays at the top level so existing clients (the CLI and the
		// browser page) keep working; the extra keys are additive.
		out := map[string]interface{}{"publicKey": options.Response, "vault_op": vaultOp,
			"push_registered": pushRegistered, "approval_deeplink": walletDeepLink(vaultOp)}
		if v2Binding != nil {
			out["binding"] = v2Binding
		}
		writeJSON(w, out)
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
		aud := m.audience
		if aud == "" {
			aud = audience
		}
		tok, err := iss.IssueVaultApprovalToken(m.sub, aud, m.vaultOp, m.nonce, m.iat, m.exp)
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
		// "approved" — this fires only after a verified assertion, so it is
		// the success line, and reads as one next to the /begin request log.
		push.CloseRequest(m.sub, vaultBadgeRequest(m.vaultOp))
		log.Printf("fido2: vault-approval APPROVED by %s (%s) completed from %s — token stashed", m.sub, m.asked, vaultPeer(r))
		writeJSON(w, map[string]interface{}{"access_token": tok, "expires_at": m.exp})
	}
}

// vaultApprovalAudience is the aud of an approval's token: the requested one,
// which must be a platform audience (each environment's vaults accept their
// own), or def when none is asked for. The token carries no roles, only the
// operation it approves, so a choice among the platform's own audiences gives
// the requester nothing the bound operation does not.
func vaultApprovalAudience(requested, def string) (string, error) {
	if requested == "" {
		return def, nil
	}
	if !tokens.IsPlatformAudience(requested) {
		return "", fmt.Errorf("audience %q is not a platform audience", requested)
	}
	return requested, nil
}

// bearerSubject verifies an `Authorization: Bearer` access token (signed by this
// IdP) and returns its `sub`.
// vaultBadgeRequest names a vault approval to the icon's count (push/badge.go):
// held in memory only, never sent.
func vaultBadgeRequest(vaultOp string) string { return "vault-approval:" + vaultOp }

// vaultBadgeExpiry is when a vault approval stops counting: its own expiry,
// or the longest a request lives when it names none.
func vaultBadgeExpiry(exp int64) time.Time {
	if exp > 0 {
		return time.Unix(exp, 0)
	}
	return time.Now().Add(5 * time.Minute)
}

// vaultOpName is the operation as the log names it: an empty one is a promote.
func vaultOpName(op string) string {
	if op == "" {
		return "promote"
	}
	return op
}

// vaultRequester says who sent a vault-approval request, for the log: the
// client and session its bearer names, and where it came from. It reads the
// bearer the handler has already accepted, and none of it is trusted for a
// decision. The address is the last hop of X-Forwarded-For, the one our own
// reverse proxy wrote. No token material is included.
func vaultRequester(r *http.Request, iss *tokens.Issuer) string {
	client, sid := "", ""
	if claims, err := iss.VerifyPlatformAccessToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err == nil {
		for _, k := range []string{"azp", "client_id"} {
			if v, _ := claims[k].(string); v != "" {
				client = v
				break
			}
		}
		sid, _ = claims["sid"].(string)
	}
	return fmt.Sprintf("client=%q sid=%q %s", logField(client), logField(sid), vaultPeer(r))
}

// vaultPeer says where a request came from, for the log: the last hop of
// X-Forwarded-For, the one our own reverse proxy wrote (else the peer), and
// the user agent. On the line that records an approval's outcome it shows
// whether the answer came from the owner's phone or from somewhere else.
func vaultPeer(r *http.Request) string {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
			ip = last
		}
	}
	return fmt.Sprintf("ip=%s ua=%q", logField(ip), logField(r.UserAgent()))
}

// logField makes a caller-supplied value safe to put on one log line: no
// control characters, and no more than a line's worth.
func logField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func bearerSubject(r *http.Request, iss *tokens.Issuer) (string, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", fmt.Errorf("missing bearer token")
	}
	claims, err := iss.VerifyPlatformAccessToken(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		return "", err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("token has no sub")
	}
	return sub, nil
}
