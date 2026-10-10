// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package oidc

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/tokens"
	"github.com/Privasys/idp/internal/voucher"
)

// App-initiated disclosures.
//
// Some requests for a holder's attributes start with no browser in sight:
// an assistant opens a Drive share link for its user, and the link asks for
// the user's name. The app must not take the value from anywhere but the
// holder's wallet, and the holder decides there.
//
// The app (authenticated by a spend proof addressed to this IdP, and only
// one the holder already lets spend their credits) names the holder and the
// claims. The IdP opens an authorize session for exactly that set, under the
// platform client the browser flow uses, and pushes the holder's wallet the
// same attribute-approval request /authorize pushes for a step-up: the
// wallet's consent path is unchanged. Once the holder approves, the app
// collects a disclosure+jwt (tokens.IssueDisclosure) carrying the values,
// addressed to it alone. It is never an access token.

// DisclosureClientID is the client an app-initiated disclosure runs under:
// the platform client, whose whitelist and requirements the browser flow for
// the same request would use.
const DisclosureClientID = "privasys-platform"

// disclosureTTL is how long the holder has to approve. Longer than a browser
// sign-in's five minutes: the holder is told in a chat, not by a QR code.
const disclosureTTL = 10 * time.Minute

// maxPendingPerApp bounds the live requests one app may hold for one holder,
// so an app cannot flood a wallet.
const maxPendingPerApp = 3

// DisclosureAuth authenticates an app from a proof and reports whether a
// holder has a standing relationship with it (spend.Handler implements both).
// resolveSubject maps a subject an app holds to the account it names (see
// internal/tokens/subject.go). Wired at start-up; identity until then.
var resolveSubject = func(sub string) string { return sub }

// SetSubjectResolver wires the per-sector subject resolution.
func SetSubjectResolver(f func(string) string) { resolveSubject = f }

type DisclosureAuth interface {
	VerifyAppProof(ctx context.Context, appID, proof string) (name string, err error)
	HasConsent(sub, appID string) bool
}

type disclosureEntry struct {
	appID string
	// sub is the account; appSub is the subject the app named it by, which
	// is what the disclosure goes back with (they differ outside the shared
	// sector, internal/tokens/subject.go).
	sub       string
	appSub    string
	sessionID string
	named     []string
	purpose   string
	expiresAt time.Time
}

// DisclosureStore holds live app-initiated disclosures by id.
type DisclosureStore struct {
	mu      sync.Mutex
	entries map[string]*disclosureEntry
}

// NewDisclosureStore creates an empty store.
func NewDisclosureStore() *DisclosureStore {
	return &DisclosureStore{entries: map[string]*disclosureEntry{}}
}

func (s *DisclosureStore) put(id string, e *disclosureEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	live := 0
	for k, v := range s.entries {
		if now.After(v.expiresAt) {
			delete(s.entries, k)
			continue
		}
		if v.appID == e.appID && v.sub == e.sub {
			live++
		}
	}
	if live >= maxPendingPerApp {
		return false
	}
	s.entries[id] = e
	return true
}

func (s *DisclosureStore) get(id string) (*disclosureEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e, true
}

func (s *DisclosureStore) drop(id string) {
	s.mu.Lock()
	delete(s.entries, id)
	s.mu.Unlock()
}

type disclosureRequest struct {
	AppID        string   `json:"app_id"`
	Proof        string   `json:"proof"`
	Sub          string   `json:"sub"`
	Attributes   []string `json:"attributes"`
	Purpose      string   `json:"purpose"`
	BillingGrant string   `json:"billing_grant"`
}

// HandleDisclosureRequest serves POST /spend/disclosures. It sits under
// /spend because it is the same relationship: an app the holder lets act for
// them, authenticated by its spend key.
func HandleDisclosureRequest(reg *clients.Registry, sessionStore *SessionStore, minter *voucher.Minter,
	push func(sub string, session *AuthSession, added []string, payload map[string]interface{}) bool,
	store *DisclosureStore, auth DisclosureAuth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req disclosureRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid json")
			return
		}
		req.Sub = strings.TrimSpace(req.Sub)
		appSub := req.Sub
		req.Sub = resolveSubject(req.Sub)
		appName, err := auth.VerifyAppProof(r.Context(), req.AppID, req.Proof)
		if err != nil {
			errorResponse(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}
		if req.Sub == "" || !auth.HasConsent(req.Sub, req.AppID) {
			// Only an app the holder already uses may ask them anything.
			errorResponse(w, http.StatusForbidden, "consent_required",
				"the holder has no standing relationship with this app")
			return
		}
		client, err := reg.Get(DisclosureClientID)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "server_error", "platform client missing")
			return
		}
		named := parseAttributesParam(strings.Join(req.Attributes, " "))
		requested := requestedAttributes("openid", named, client)
		if len(requested) == 0 {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "no attribute this client may request")
			return
		}
		if slices.Contains(requested, presenceAttribute) {
			// The presence ceremony needs the wallet's full flow, never a push.
			errorResponse(w, http.StatusBadRequest, "invalid_request", "presence cannot be requested this way")
			return
		}
		reqs := attributeRequirements("openid", named, client)

		session := &AuthSession{
			SessionID:           generateID(),
			ClientID:            DisclosureClientID,
			Scope:               "openid",
			NamedAttributes:     named,
			RequestedKeys:       requested,
			CodeChallenge:       generateID(), // never redeemed by a client
			CodeChallengeMethod: "S256",
			CreatedAt:           time.Now(),
			ExpiresAt:           time.Now().Add(disclosureTTL),
		}
		payload := map[string]interface{}{
			"origin":                "privasys.id",
			"sessionId":             session.SessionID,
			"rpId":                  "privasys.id",
			"clientId":              DisclosureClientID,
			"appName":               orName(appName),
			"brokerUrl":             "wss://relay.privasys.org/relay",
			"requestedAttributes":   requested,
			"attributeRequirements": reqs,
		}
		if p := strings.TrimSpace(req.Purpose); p != "" {
			// Shown by a wallet that knows the field; ignored by one that does not.
			payload["purpose"] = p
		}
		vouchers, err := mintDisclosureVouchers(r.Context(), minter, client, reqs, strings.TrimSpace(req.BillingGrant))
		if err == voucher.ErrInsufficient {
			errorResponse(w, http.StatusPaymentRequired, "insufficient_credits",
				"insufficient credits for the requested attributes")
			return
		} else if err != nil {
			log.Printf("disclosure: mint vouchers: %v", err)
			errorResponse(w, http.StatusBadGateway, "voucher_error", "could not reserve attribute credits")
			return
		}
		if len(vouchers) > 0 {
			payload["disclosureVouchers"] = vouchers
		}

		id := generateID()
		entry := &disclosureEntry{
			appID: req.AppID, sub: req.Sub, appSub: appSub, sessionID: session.SessionID,
			named: named, purpose: strings.TrimSpace(req.Purpose), expiresAt: session.ExpiresAt,
		}
		if !store.put(id, entry) {
			errorResponse(w, http.StatusTooManyRequests, "too_many_requests",
				"this app already has requests waiting for the holder")
			return
		}
		sessionStore.Create(session)
		// Every requested attribute is shown, not a delta against the
		// platform client's standing grant: these values go to someone new.
		// The pairwise subject rides every sign-in and is not asked about.
		if !push(req.Sub, session, subtractKeys(requested, []string{"sub"}), payload) {
			store.drop(id)
			errorResponse(w, http.StatusConflict, "no_push",
				"the holder has no wallet that can receive this request")
			return
		}
		log.Printf("disclosure: %s asked holder for %v (request %s…)", req.AppID, requested, id[:8])
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         id,
			"status":     "pending",
			"attributes": requested,
			"expires_in": int(disclosureTTL.Seconds()),
		})
	}
}

// HandleDisclosureResult serves POST /spend/disclosures/{id}: the asking app
// collects the outcome. Pending until the holder approves; then a single
// disclosure+jwt, after which the request is gone.
func HandleDisclosureResult(reg *clients.Registry, sessionStore *SessionStore, codes *CodeStore,
	issuer *tokens.Issuer, store *DisclosureStore, auth DisclosureAuth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AppID string `json:"app_id"`
			Proof string `json:"proof"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid_request", "invalid json")
			return
		}
		if _, err := auth.VerifyAppProof(r.Context(), req.AppID, req.Proof); err != nil {
			errorResponse(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}
		id := r.PathValue("id")
		entry, ok := store.get(id)
		if !ok || entry.appID != req.AppID {
			errorResponse(w, http.StatusNotFound, "not_found", "no such request, or it expired")
			return
		}
		session, ok := sessionStore.Get(entry.sessionID)
		if !ok {
			store.drop(id)
			errorResponse(w, http.StatusGone, "expired", "the holder did not approve in time")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if session.AuthCode == "" {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "pending"})
			return
		}
		ac, ok := codes.Consume(session.AuthCode)
		store.drop(id)
		if !ok || ac.UserID != entry.sub {
			errorResponse(w, http.StatusGone, "expired", "the approval is no longer available")
			return
		}
		// The same narrowing the token endpoint applies: what was asked for,
		// within the client's whitelist.
		attrs := filterAttributesRequested(ac.Attributes, "openid", entry.named)
		out := map[string]string{}
		if client, err := reg.Get(DisclosureClientID); err == nil {
			for _, key := range client.RequiredAttributes {
				if v, ok := attrs[key]; ok {
					out[key] = v
				}
			}
		}
		now := time.Now()
		tok, err := issuer.IssueDisclosure(tokens.DisclosureClaims{
			Subject: entry.appSub, AppID: entry.appID, Attributes: out, Purpose: entry.purpose,
			IssuedAt: now, Expiry: now.Add(5 * time.Minute), JTI: generateID(),
		})
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "server_error", "issuance failed")
			return
		}
		log.Printf("disclosure: holder approved request %s… for %s", id[:8], entry.appID)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "approved", "disclosure": tok})
	}
}

func orName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "Privasys"
	}
	return name
}
