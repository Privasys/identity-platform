// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

// One approval for a list of vault operations.
//
// Rolling a host promotes every key on it, and each promote carries its own
// operation-bound token (vault_approval.go). A batch lets the owner approve the
// whole list with one WebAuthn assertion:
//
//	POST /fido2/vault-approval/batch/begin     (Bearer owner token; the list)
//	    -> WebAuthn options whose challenge IS the batch binding
//	GET  /fido2/vault-approval/batch/pending?challenge=<batch_id>   (the wallet)
//	POST /fido2/vault-approval/batch/complete?challenge=<batch_id>  (the assertion)
//	GET  /fido2/vault-approval/batch/token?challenge=<batch_id>     (Bearer owner)
//	    -> one ordinary operation-bound token per entry
//
// The vaults and the runtime see exactly the token they accept today: each one
// binds a single (handle, measurement, policy_version, nonce, exp). The wallet
// recomputes every vault_op and the batch binding from the entries it displays
// and refuses a list that does not hash to the challenge, so the list the owner
// reads is the list the signature covers.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Privasys/idp/internal/push"
	"github.com/Privasys/idp/internal/tokens"
)

// vaultBatchDomain separates a batch binding from every other WebAuthn
// challenge. It MUST match every client that recomputes the binding.
const vaultBatchDomain = "privasys-vault-approval-batch-v1"

const (
	// vaultBatchMaxEntries fits a host roll and keeps the card readable.
	vaultBatchMaxEntries = 32
	// vaultBatchMaxLabelRunes bounds the description shown as the card's title.
	vaultBatchMaxLabelRunes = 120
	// vaultBatchMaxHandleBytes bounds one handle in the binding.
	vaultBatchMaxHandleBytes = 512
)

// vaultDigestHex is a lowercase SHA-256 digest, the only measurement form a
// batch accepts.
var vaultDigestHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// vaultBatchContext is advisory display context for one entry. It is not part
// of any binding: the wallet derives what it shows as fact from the handle.
type vaultBatchContext struct {
	AppName   string `json:"app_name,omitempty"`
	Version   string `json:"version,omitempty"`
	Source    string `json:"source,omitempty"`
	KeyType   string `json:"key_type,omitempty"`
	Summary   string `json:"summary,omitempty"`
	AppID     string `json:"app_id,omitempty"`
	VersionID string `json:"version_id,omitempty"`
}

// vaultBatchEntry is one operation of a batch.
type vaultBatchEntry struct {
	Operation         string            `json:"operation"`
	Handle            string            `json:"handle"`
	MeasurementDigest string            `json:"measurement_digest"`
	PolicyVersion     uint64            `json:"policy_version"`
	Nonce             string            `json:"nonce,omitempty"`
	VaultOp           string            `json:"vault_op,omitempty"`
	Context           vaultBatchContext `json:"context,omitempty"`
}

// vaultBatchMeta is what /complete needs to issue the tokens.
type vaultBatchMeta struct {
	sub     string
	batchID string
	label   string
	iat     int64
	exp     int64
	entries []vaultBatchEntry
}

// vaultBatchHiddenRune reports a character that changes how text reads without
// being seen: controls, format and bidirectional marks, and line separators.
// The wallet refuses the same set on its card; refusing it here tells the
// initiator why, instead of leaving the owner with a card that will not open.
func vaultBatchHiddenRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
		r == 0x180e || r == 0x2028 || r == 0x2029 || (r >= 0x2060 && r <= 0x206f)
}

// validateVaultBatch checks a requested batch and returns its entries in
// canonical order. Only promotes and app policies may be batched: an export, a
// key-policy update or a recovery releases or changes control of a key, and
// stays one approval each.
func validateVaultBatch(label string, entries []vaultBatchEntry) ([]vaultBatchEntry, error) {
	if strings.TrimSpace(label) == "" || label != strings.TrimSpace(label) {
		return nil, errors.New("label required, with no surrounding space")
	}
	if !utf8.ValidString(label) || utf8.RuneCountInString(label) > vaultBatchMaxLabelRunes {
		return nil, fmt.Errorf("label must be valid text of at most %d characters", vaultBatchMaxLabelRunes)
	}
	for _, r := range label {
		if vaultBatchHiddenRune(r) {
			return nil, errors.New("label must not contain control, format or bidirectional characters")
		}
	}
	if len(entries) == 0 || len(entries) > vaultBatchMaxEntries {
		return nil, fmt.Errorf("a batch holds 1 to %d entries", vaultBatchMaxEntries)
	}
	out := make([]vaultBatchEntry, len(entries))
	copy(out, entries)
	seen := make(map[string]bool, len(out))
	for i := range out {
		e := &out[i]
		if e.Handle == "" || len(e.Handle) > vaultBatchMaxHandleBytes {
			return nil, fmt.Errorf("entry %d: handle required, at most %d bytes", i, vaultBatchMaxHandleBytes)
		}
		if !utf8.ValidString(e.Handle) {
			return nil, fmt.Errorf("entry %d: handle must be valid text", i)
		}
		for _, r := range e.Handle {
			if unicode.IsSpace(r) || vaultBatchHiddenRune(r) {
				return nil, fmt.Errorf("entry %d: handle must not contain spaces, control, format or bidirectional characters", i)
			}
		}
		switch e.Operation {
		case "promote":
		case "app-policy":
			if !strings.HasPrefix(e.Handle, "app:") || !strings.HasSuffix(e.Handle, ":policy") {
				return nil, fmt.Errorf("entry %d: app-policy handle must be app:<app-id>:policy", i)
			}
		default:
			return nil, fmt.Errorf("entry %d: operation %q cannot be batched", i, e.Operation)
		}
		if !vaultDigestHex.MatchString(e.MeasurementDigest) {
			return nil, fmt.Errorf("entry %d: measurement_digest must be 64 lowercase hex characters", i)
		}
		key := e.Operation + " " + e.Handle
		if seen[key] {
			return nil, fmt.Errorf("entry %d: %s appears twice", i, key)
		}
		seen[key] = true
		e.Nonce, e.VaultOp = "", ""
		e.Context.Summary = clipSummary(e.Context.Summary)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Handle != out[b].Handle {
			return out[a].Handle < out[b].Handle
		}
		return out[a].Operation < out[b].Operation
	})
	return out, nil
}

// computeVaultBatchBinding hashes the canonical newline-joined batch. Every
// value is rendered as UTF-8 text so the digest is identical in Go and in the
// wallet's TypeScript; validateVaultBatch keeps newlines out of each value.
func computeVaultBatchBinding(label string, exp int64, entries []vaultBatchEntry) [32]byte {
	var b strings.Builder
	b.WriteString(vaultBatchDomain)
	b.WriteByte('\n')
	b.WriteString(label)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatInt(exp, 10))
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(len(entries)))
	for _, e := range entries {
		b.WriteByte('\n')
		b.WriteString(e.Operation)
		b.WriteByte(' ')
		b.WriteString(e.VaultOp)
	}
	return sha256.Sum256([]byte(b.String()))
}

// bindVaultBatch gives every entry its nonce and vault_op and returns the batch
// id: the base64url batch binding, which is also the WebAuthn challenge.
func bindVaultBatch(label string, exp int64, entries []vaultBatchEntry, newNonce func() (string, error)) (string, [32]byte, error) {
	for i := range entries {
		nonce, err := newNonce()
		if err != nil {
			return "", [32]byte{}, err
		}
		e := &entries[i]
		binding := computeVaultApprovalBinding(e.Handle, e.MeasurementDigest, e.PolicyVersion, nonce, exp)
		e.Nonce = nonce
		e.VaultOp = base64.RawURLEncoding.EncodeToString(binding[:])
	}
	batch := computeVaultBatchBinding(label, exp, entries)
	return base64.RawURLEncoding.EncodeToString(batch[:]), batch, nil
}

func newVaultNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// vaultBatchToken is one issued token, named by the entry it authorises.
type vaultBatchToken struct {
	Operation   string `json:"operation"`
	Handle      string `json:"handle"`
	VaultOp     string `json:"vault_op"`
	AccessToken string `json:"access_token"`
}

type vaultBatchPending struct {
	sub       string
	label     string
	optionsJS json.RawMessage
	entries   []vaultBatchEntry
	expiresAt time.Time
}

type vaultBatchResult struct {
	sub       string
	tokens    []vaultBatchToken
	declined  bool // the owner declined on the phone: no tokens will come
	expiresAt time.Time
}

// vaultBatchStore holds the open batches and the tokens waiting for collection.
// An owner has at most one open batch, so no stale card waits on the phone.
type vaultBatchStore struct {
	mu      sync.Mutex
	pending map[string]*vaultBatchPending
	open    map[string]string // sub -> batch id
	results map[string]vaultBatchResult
}

func newVaultBatchStore() *vaultBatchStore {
	s := &vaultBatchStore{
		pending: make(map[string]*vaultBatchPending),
		open:    make(map[string]string),
		results: make(map[string]vaultBatchResult),
	}
	go func() {
		for {
			time.Sleep(time.Minute)
			s.cleanup(time.Now())
		}
	}()
	return s
}

// put records a batch as its owner's only open one and returns the batch it
// replaced, if any.
func (s *vaultBatchStore) put(batchID string, p *vaultBatchPending) (replaced string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.open[p.sub]; ok && old != batchID {
		delete(s.pending, old)
		replaced = old
	}
	s.open[p.sub] = batchID
	s.pending[batchID] = p
	return replaced
}

func (s *vaultBatchStore) get(batchID string) (*vaultBatchPending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[batchID]
	if !ok || time.Now().After(p.expiresAt) {
		return nil, false
	}
	return p, true
}

// finish closes a batch and stashes its tokens for the owner to collect.
func (s *vaultBatchStore) finish(batchID, sub string, tokens []vaultBatchToken, exp int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, batchID)
	if s.open[sub] == batchID {
		delete(s.open, sub)
	}
	s.results[batchID] = vaultBatchResult{sub: sub, tokens: tokens, expiresAt: time.Unix(exp, 0)}
}

// decline closes an open batch the owner refused, so the initiator's poll ends.
func (s *vaultBatchStore) decline(batchID string) (sub string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[batchID]
	if !ok || time.Now().After(p.expiresAt) {
		return "", false
	}
	delete(s.pending, batchID)
	if s.open[p.sub] == batchID {
		delete(s.open, p.sub)
	}
	s.results[batchID] = vaultBatchResult{sub: p.sub, declined: true, expiresAt: p.expiresAt}
	return p.sub, true
}

// take returns a batch's result to its owner, once: the tokens, or a refusal.
func (s *vaultBatchStore) take(batchID, sub string) (vaultBatchResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[batchID]
	if !ok || r.sub != sub || time.Now().After(r.expiresAt) {
		return vaultBatchResult{}, false
	}
	delete(s.results, batchID)
	return r, true
}

func (s *vaultBatchStore) cleanup(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.pending {
		if now.After(p.expiresAt) {
			delete(s.pending, id)
			if s.open[p.sub] == id {
				delete(s.open, p.sub)
			}
		}
	}
	for id, r := range s.results {
		if now.After(r.expiresAt) {
			delete(s.results, id)
		}
	}
}

// VaultApprovalBatchBegin handles POST /fido2/vault-approval/batch/begin.
//
// Auth: Authorization: Bearer <owner access token>. Body:
//
//	{"label":"...", "ttl_seconds":300, "entries":[{"operation":"promote",
//	 "handle":"...", "measurement_digest":"<hex>", "policy_version":N, "context":{...}}]}
func (h *Handler) VaultApprovalBatchBegin(iss *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub, err := bearerSubject(r, iss)
		if err != nil {
			errorJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		var req struct {
			Label      string            `json:"label"`
			TTLSeconds int64             `json:"ttl_seconds"`
			Entries    []vaultBatchEntry `json:"entries"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
			errorJSON(w, http.StatusBadRequest, "invalid body")
			return
		}
		entries, err := validateVaultBatch(req.Label, req.Entries)
		if err != nil {
			errorJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		ttl := req.TTLSeconds
		if ttl <= 0 {
			ttl = vaultApprovalMaxTTL
		}
		if ttl > vaultApprovalMaxTTL {
			ttl = vaultApprovalMaxTTL
		}
		now := time.Now().Unix()
		exp := now + ttl
		batchID, binding, err := bindVaultBatch(req.Label, exp, entries, newVaultNonce)
		if err != nil {
			errorJSON(w, http.StatusInternalServerError, "nonce generation failed")
			return
		}

		creds, err := h.loadCredentials(sub)
		if err != nil || len(creds) == 0 {
			errorJSON(w, http.StatusNotFound, "no credentials for user")
			return
		}
		user := &idpUser{ID: []byte(sub), Name: sub, Credentials: creds}
		options, sessionData, err := h.webAuthn.BeginLogin(user)
		if err != nil {
			log.Printf("fido2/vault-approval/batch/begin: %v", err)
			errorJSON(w, http.StatusInternalServerError, "begin failed")
			return
		}
		options.Response.Challenge = protocol.URLEncodedBase64(binding[:])
		sessionData.Challenge = batchID
		h.challenges.put(batchID, &challengeEntry{
			sessionData: sessionData,
			user:        user,
			expiresAt:   time.Unix(exp, 0),
			vaultBatch: &vaultBatchMeta{
				sub: sub, batchID: batchID, label: req.Label, iat: now, exp: exp, entries: entries,
			},
		})
		optionsJS, _ := json.Marshal(options)
		if replaced := h.vaultBatches.put(batchID, &vaultBatchPending{
			sub: sub, label: req.Label, optionsJS: optionsJS, entries: entries, expiresAt: time.Unix(exp, 0),
		}); replaced != "" {
			h.challenges.pop(replaced)
		}
		pushRegistered := h.pushVaultBatch(sub, batchID, len(entries))
		log.Printf("fido2: vault-approval batch requested by %s (%d entries, batch %s…, ttl %ds, push_registered=%t)",
			sub, len(entries), batchID[:12], ttl, pushRegistered)
		writeJSON(w, map[string]interface{}{
			"batch_id":          batchID,
			"publicKey":         options.Response,
			"exp":               exp,
			"entries":           entries,
			"push_registered":   pushRegistered,
			"approval_deeplink": "privasys-wallet://vault-approvals?batch_id=" + url.QueryEscape(batchID),
		})
	}
}

func vaultBatchPushBody(count int) string {
	if count == 1 {
		return "1 operation needs your approval"
	}
	return fmt.Sprintf("%d operations need your approval", count)
}

// pushVaultBatch nudges the owner's wallets. Only the routing type and the
// capability travel through the push service.
func (h *Handler) pushVaultBatch(sub, batchID string, count int) bool {
	pushTokens := h.db.GetPushTokens(sub)
	for _, pushToken := range pushTokens {
		go func(token string) {
			if err := push.Notify(context.Background(), h.db, sub, push.Message{
				Token: token,
				Title: "Vault approval",
				Body:  vaultBatchPushBody(count),
				Data:  map[string]string{"type": "vault-approval-batch", "batch_id": batchID},
			}); err != nil {
				log.Printf("fido2/vault-approval/batch: push send: %v", err)
			}
		}(pushToken)
	}
	return len(pushTokens) > 0
}

// VaultApprovalBatchPending handles GET
// /fido2/vault-approval/batch/pending?challenge=<batch_id>: a capability-based
// fetch with no bearer, as for a single approval (see VaultApprovalPending).
// Approving still requires the owner's WebAuthn assertion.
func (h *Handler) VaultApprovalBatchPending() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		batchID := r.URL.Query().Get("challenge")
		p, ok := h.vaultBatches.get(batchID)
		if batchID == "" || !ok {
			errorJSON(w, http.StatusNotFound, "no pending batch for this challenge")
			return
		}
		writeJSON(w, map[string]interface{}{
			"batch_id":   batchID,
			"label":      p.label,
			"exp":        p.expiresAt.Unix(),
			"options":    p.optionsJS,
			"entries":    p.entries,
			"expires_at": p.expiresAt.Unix(),
		})
	}
}

// VaultApprovalBatchComplete handles POST
// /fido2/vault-approval/batch/complete?challenge=<batch_id>. The tokens are
// stashed for the owner who began the batch: the phone that approves never
// holds them.
func (h *Handler) VaultApprovalBatchComplete(iss *tokens.Issuer, audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		batchID := r.URL.Query().Get("challenge")
		entry, ok := h.challenges.pop(batchID)
		if !ok || entry.vaultBatch == nil {
			errorJSON(w, http.StatusBadRequest, "challenge expired or not found")
			return
		}
		if _, err := h.webAuthn.FinishLogin(entry.user, *entry.sessionData, r); err != nil {
			log.Printf("fido2/vault-approval/batch/complete: %v", err)
			errorJSON(w, http.StatusBadRequest, "verification failed")
			return
		}
		m := entry.vaultBatch
		issued := make([]vaultBatchToken, 0, len(m.entries))
		for _, e := range m.entries {
			tok, err := iss.IssueVaultApprovalToken(m.sub, audience, e.VaultOp, e.Nonce, m.iat, m.exp)
			if err != nil {
				log.Printf("fido2/vault-approval/batch/complete: issue: %v", err)
				errorJSON(w, http.StatusInternalServerError, "token issuance failed")
				return
			}
			issued = append(issued, vaultBatchToken{Operation: e.Operation, Handle: e.Handle, VaultOp: e.VaultOp, AccessToken: tok})
		}
		h.vaultBatches.finish(m.batchID, m.sub, issued, m.exp)
		log.Printf("fido2: vault-approval batch APPROVED by %s (%d entries, batch %s…, label %q)",
			m.sub, len(issued), m.batchID[:12], m.label)
		writeJSON(w, map[string]interface{}{"status": "approved", "count": len(issued)})
	}
}

// VaultApprovalBatchToken handles GET
// /fido2/vault-approval/batch/token?challenge=<batch_id>. Auth: the owner
// bearer that began the batch. 202 while pending, then the tokens, once.
func (h *Handler) VaultApprovalBatchToken(iss *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub, err := bearerSubject(r, iss)
		if err != nil {
			errorJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		batchID := r.URL.Query().Get("challenge")
		if batchID == "" {
			errorJSON(w, http.StatusBadRequest, "challenge required")
			return
		}
		res, ok := h.vaultBatches.take(batchID, sub)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
			return
		}
		if res.declined {
			writeDeclined(w)
			return
		}
		writeJSON(w, map[string]interface{}{"tokens": res.tokens})
	}
}

// writeDeclined is the initiator's terminal answer once the owner declined.
func writeDeclined(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	_, _ = w.Write([]byte(`{"status":"declined"}`))
}

// VaultApprovalDecline handles POST /fido2/vault-approval/decline?challenge=<vault_op>.
//
// The capability is the authority, as for GET pending: a decline can only end a
// request, never approve one. The challenge is consumed first, so a decline and
// an approval cannot both succeed. 204 when the request was dropped, 404 when it
// is unknown, already answered or expired.
func (h *Handler) VaultApprovalDecline() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vaultOp := r.URL.Query().Get("challenge")
		entry, ok := h.challenges.popIf(vaultOp, func(e *challengeEntry) bool { return e.vaultApproval != nil })
		if vaultOp == "" || !ok {
			errorJSON(w, http.StatusNotFound, "no pending approval for this challenge")
			return
		}
		m := entry.vaultApproval
		h.vaultPending.remove(vaultOp)
		h.vaultResults.decline(vaultOp, m.sub, time.Unix(m.exp, 0))
		log.Printf("fido2: vault-approval DECLINED by the owner's wallet (sub %s, vault_op %s…)", m.sub, vaultOp[:min(12, len(vaultOp))])
		w.WriteHeader(http.StatusNoContent)
	}
}

// VaultApprovalBatchDecline handles POST
// /fido2/vault-approval/batch/decline?challenge=<batch_id>, on the same terms
// as VaultApprovalDecline.
func (h *Handler) VaultApprovalBatchDecline() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		batchID := r.URL.Query().Get("challenge")
		_, ok := h.challenges.popIf(batchID, func(e *challengeEntry) bool { return e.vaultBatch != nil })
		if batchID == "" || !ok {
			errorJSON(w, http.StatusNotFound, "no pending batch for this challenge")
			return
		}
		sub, _ := h.vaultBatches.decline(batchID)
		log.Printf("fido2: vault-approval batch DECLINED by the owner's wallet (sub %s, batch %s…)", sub, batchID[:min(12, len(batchID))])
		w.WriteHeader(http.StatusNoContent)
	}
}
