// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

// Attribute step-up approvals (the push arm of attribute step-up by push).
//
// /authorize computes the delta of a widened request (oidc.AttributeStepUp)
// and calls the pusher below: it records a pending approval keyed by a fresh
// capability and pushes the holder's wallet. The wallet fetches the pending
// request over TLS, shows ONLY the delta, gates on biometric, signs the
// assertion with its existing fido2 credential — the WebAuthn challenge IS
// the hash committing to the session id, the client and the EXACT requested
// key set — and POSTs it together with the attribute values for the full
// requested set to /complete, which finishes the OIDC authorize session
// exactly as the QR ceremony would. The browser's status poll then collects
// the code with no QR ever shown.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Privasys/idp/internal/oidc"
	"github.com/Privasys/idp/internal/tokens"
)

// attributeApprovalDomain separates this binding from every other digest a
// wallet credential signs (vault approvals, session-relay bindings).
const attributeApprovalDomain = "privasys-attribute-approval/v1"

// computeAttributeApprovalBinding commits an approval to one authorize
// session, one client, and the exact requested key set. Approving "share
// your date of birth" must never authorise a request that also names a
// passport number, and an approval for session A must be worthless on
// session B — both fall out of hashing the whole tuple.
func computeAttributeApprovalBinding(sessionID, clientID string, requestedKeys []string, exp int64) [32]byte {
	keys := append([]string(nil), requestedKeys...)
	sort.Strings(keys)
	// JSON-encode the sorted list so the encoding is injective — a plain
	// join would let two different lists render identically. Only the IdP
	// ever computes this hash (at push time and at completion), so the
	// encoding is not a cross-implementation contract.
	keysJSON, _ := json.Marshal(keys)
	input := fmt.Sprintf("%s\n%s\n%s\n%s\n%d",
		attributeApprovalDomain, sessionID, clientID, keysJSON, exp)
	return sha256.Sum256([]byte(input))
}

// attrPendingEntry is one pushed approval awaiting the wallet. Everything
// the completion needs is fixed at push time; the WebAuthn session data
// carries the binding as its challenge, so a verified assertion proves the
// holder approved exactly this request.
type attrPendingEntry struct {
	sub         string
	sessionID   string
	clientID    string
	added       []string
	binding     [32]byte
	optionsJS   json.RawMessage
	payload     map[string]interface{}
	sessionData *webauthn.SessionData
	user        *idpUser
	expiresAt   time.Time
}

// attrPendingStore holds pending approvals keyed by capability (32 random
// bytes, base64url). Entries expire with the authorize session and are
// popped (single use) on completion.
type attrPendingStore struct {
	mu      sync.Mutex
	pending map[string]*attrPendingEntry
}

func newAttrPendingStore() *attrPendingStore {
	s := &attrPendingStore{pending: make(map[string]*attrPendingEntry)}
	go func() {
		for {
			time.Sleep(time.Minute)
			s.cleanup()
		}
	}()
	return s
}

func (s *attrPendingStore) put(cap string, e *attrPendingEntry) {
	s.mu.Lock()
	s.pending[cap] = e
	s.mu.Unlock()
}

// get returns the live entry without consuming it (the wallet's fetch).
func (s *attrPendingStore) get(cap string) (*attrPendingEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.pending[cap]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e, true
}

// pop consumes the live entry — one approval, one completion attempt.
func (s *attrPendingStore) pop(cap string) (*attrPendingEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.pending[cap]
	delete(s.pending, cap)
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e, true
}

// listFor returns the live pending approvals owned by sub.
func (s *attrPendingStore) listFor(sub string) []map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]map[string]interface{}, 0)
	for cap, e := range s.pending {
		if e.sub != sub || now.After(e.expiresAt) {
			continue
		}
		out = append(out, attrPendingJSON(cap, e))
	}
	return out
}

func (s *attrPendingStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.pending {
		if now.After(v.expiresAt) {
			delete(s.pending, k)
		}
	}
}

func attrPendingJSON(cap string, e *attrPendingEntry) map[string]interface{} {
	return map[string]interface{}{
		"approval":   cap,
		"options":    e.optionsJS,
		"session_id": e.sessionID,
		"client_id":  e.clientID,
		"added":      e.added,
		"payload":    e.payload,
		"expires_at": e.expiresAt.Unix(),
	}
}

// AttributeApprovalPusher returns the /authorize hook (oidc.AttributeStepUp.Push):
// record a pending approval for the delta and push the holder's wallet.
// Returns false — caller falls back to the ceremony — when the holder has no
// push token, no credentials, or the push machinery fails.
func (h *Handler) AttributeApprovalPusher() func(sub string, session *oidc.AuthSession, added []string, payload map[string]interface{}) bool {
	return func(sub string, session *oidc.AuthSession, added []string, payload map[string]interface{}) bool {
		pushToken := h.db.GetPushToken(sub)
		if pushToken == "" {
			return false
		}
		creds, err := h.loadCredentials(sub)
		if err != nil || len(creds) == 0 {
			return false
		}
		user := &idpUser{ID: []byte(sub), Name: sub, Credentials: creds}
		options, sessionData, err := h.webAuthn.BeginLogin(user)
		if err != nil {
			log.Printf("fido2/attribute-approval: begin login: %v", err)
			return false
		}
		// Override the random challenge with the session/set binding, so
		// the verified assertion IS the approval of exactly this request.
		exp := session.ExpiresAt.Unix()
		binding := computeAttributeApprovalBinding(
			session.SessionID, session.ClientID, session.RequestedKeys, exp)
		options.Response.Challenge = protocol.URLEncodedBase64(binding[:])
		sessionData.Challenge = base64.RawURLEncoding.EncodeToString(binding[:])

		capBytes := make([]byte, 32)
		if _, err := rand.Read(capBytes); err != nil {
			return false
		}
		capability := base64.RawURLEncoding.EncodeToString(capBytes)
		optionsJS, _ := json.Marshal(options)
		h.attrPending.put(capability, &attrPendingEntry{
			sub:         sub,
			sessionID:   session.SessionID,
			clientID:    session.ClientID,
			added:       added,
			binding:     binding,
			optionsJS:   optionsJS,
			payload:     payload,
			sessionData: sessionData,
			user:        user,
			// The approval expires WITH the authorize session, never on a
			// longer clock of its own.
			expiresAt: session.ExpiresAt,
		})
		go sendAttributeApprovalPush(pushToken, capability, len(added))
		log.Printf("fido2: attribute-approval pushed to holder of client %s (session %s…, +%d keys)",
			session.ClientID, session.SessionID[:8], len(added))
		return true
	}
}

// sendAttributeApprovalPush delivers an Expo push tagged
// type:"attribute-approval". Data carries only the routing type and the
// capability — the wallet fetches the delta and descriptor from /pending
// over TLS, so no request material transits third-party push infrastructure.
// Values in data must be strings (Expo constraint).
func sendAttributeApprovalPush(pushToken, capability string, addedCount int) {
	body := "An app you use is asking to receive more of your data — tap to review"
	if addedCount == 1 {
		body = "An app you use is asking to receive one more piece of your data — tap to review"
	}
	msg := []map[string]interface{}{{
		"to":    pushToken,
		"sound": "default",
		// APNs priority 10. See the note in admin/notify.go: Expo's default
		// maps to priority 5, which lets iOS defer delivery for power.
		"priority": "high",
		"title":    "Data request",
		"body":     body,
		"data": map[string]string{
			"type":     "attribute-approval",
			"approval": capability,
		},
	}}
	payload, _ := json.Marshal(msg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://exp.host/--/api/v2/push/send", bytes.NewReader(payload))
	if err != nil {
		log.Printf("fido2/attribute-approval: build push: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("fido2/attribute-approval: push send: %v", err)
		return
	}
	resp.Body.Close()
}

// AttributeApprovalPending handles GET /fido2/attribute-approval/pending.
//
// Two access modes, mirroring the vault-approval endpoint:
//
//   - ?challenge=<capability>: capability-based single fetch, no bearer.
//     The capability is 256-bit, short-TTL, single-completion, delivered
//     only via the holder's push; possessing it authorises VIEWING this one
//     request. Approval still requires the WebAuthn assertion on /complete.
//
//   - no challenge: owner-bearer list (wallet session or OIDC token), for a
//     wallet that opens with an undelivered push in the tray.
func (h *Handler) AttributeApprovalPending(iss *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if capability := r.URL.Query().Get("challenge"); capability != "" {
			e, ok := h.attrPending.get(capability)
			if !ok {
				errorJSON(w, http.StatusNotFound, "no pending approval for this challenge")
				return
			}
			writeJSON(w, map[string]interface{}{
				"pending": []map[string]interface{}{attrPendingJSON(capability, e)},
			})
			return
		}
		sub, err := h.resolveSubject(r, iss)
		if err != nil {
			errorJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeJSON(w, map[string]interface{}{"pending": h.attrPending.listFor(sub)})
	}
}

// AttributeApprovalComplete handles
// POST /fido2/attribute-approval/complete?challenge=<capability>.
//
// Body:
//
//	{"assertion": <standard WebAuthn AuthenticatorAssertionResponse>,
//	 "attributes": {"<key>": "<value>", ...}}
//
// `attributes` carries the values for the FULL requested set (the wallet
// resolves them on-device; nothing is stored server-side between sessions),
// while the consent screen showed only the delta. On success the OIDC
// session completes and the browser's poll collects the code.
func (h *Handler) AttributeApprovalComplete(codes *oidc.CodeStore, sessionStore *oidc.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		capability := r.URL.Query().Get("challenge")
		// pop: one approval, one completion attempt — a replay lands here.
		entry, ok := h.attrPending.pop(capability)
		if !ok {
			errorJSON(w, http.StatusBadRequest, "challenge expired or not found")
			return
		}
		var body struct {
			Assertion  json.RawMessage   `json:"assertion"`
			Attributes map[string]string `json:"attributes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Assertion) == 0 {
			errorJSON(w, http.StatusBadRequest, "assertion required")
			return
		}
		parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body.Assertion))
		if err != nil {
			errorJSON(w, http.StatusBadRequest, "malformed assertion")
			return
		}
		if _, err := h.webAuthn.ValidateLogin(entry.user, *entry.sessionData, parsed); err != nil {
			log.Printf("fido2/attribute-approval/complete: %v", err)
			errorJSON(w, http.StatusBadRequest, fmt.Sprintf("verification failed: %s", err))
			return
		}
		session, ok := sessionStore.Get(entry.sessionID)
		if !ok {
			errorJSON(w, http.StatusGone, "authorize session expired")
			return
		}
		// Re-derive the binding from the session's OWN requested set and
		// compare it to what was approved. The session is immutable, so this
		// is the belt to the challenge's braces: an approval can only ever
		// complete the exact request the holder saw.
		expected := computeAttributeApprovalBinding(
			session.SessionID, session.ClientID, session.RequestedKeys, session.ExpiresAt.Unix())
		if subtle.ConstantTimeCompare(expected[:], entry.binding[:]) != 1 {
			errorJSON(w, http.StatusBadRequest, "approval does not match this session's request")
			return
		}
		authCode := codes.Create(&oidc.AuthCode{
			ClientID:            session.ClientID,
			RedirectURI:         session.RedirectURI,
			UserID:              entry.sub,
			Scope:               session.Scope,
			Nonce:               session.Nonce,
			ACRValues:           session.ACRValues,
			NamedAttributes:     session.NamedAttributes,
			CodeChallenge:       session.CodeChallenge,
			CodeChallengeMethod: session.CodeChallengeMethod,
			AuthTime:            time.Now(),
			Attributes:          body.Attributes,
			// Wallet class only via /session/assert-wallet (WIA PoP), same
			// as every other completion path — the wallet asserts alongside
			// this call and MarkWalletAsserted patches either order.
			WalletVerified: session.WalletAsserted,
		})
		if !sessionStore.CompleteIfPending(entry.sessionID, entry.sub, authCode) {
			// A concurrent ceremony (QR fallback) won the race; the approval
			// must not override what the holder just completed interactively.
			errorJSON(w, http.StatusConflict, "session already completed")
			return
		}
		log.Printf("fido2: attribute-approval APPROVED by holder (session %s…, client %s)",
			entry.sessionID[:8], entry.clientID)
		writeJSON(w, map[string]interface{}{"status": "approved"})
	}
}
