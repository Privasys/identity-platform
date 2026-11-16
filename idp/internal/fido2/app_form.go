// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

// The holder's answer to an app form (internal/appmessages/form.go).
//
// An app asks a question by sending a form; the wallet draws it from the
// sealed payload and the holder taps one of the actions it offers. The answer
// must reach the app as something only the holder could have produced, for
// that form and that action alone, so:
//
//  1. begin: the wallet names the form and the action. The IdP checks the
//     form is this holder's, still open, and offers that action, and starts a
//     WebAuthn login whose challenge commits to the app, the form's
//     reference, the form's digest and the action.
//  2. answer: the wallet returns the assertion, signed with the identity's
//     privasys.id passkey behind the biometric. The IdP verifies it, takes the
//     form off the list (one answer per form, ever), and signs an answer
//     token naming the subject the app addressed.
//
// The wallet then posts the token to the app over attested RA-TLS. The app
// checks it against this IdP's keys, and that its digest is the hash of the
// exact form it sent, so a form changed on the way fails there.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Privasys/idp/internal/appmessages"
	"github.com/Privasys/idp/internal/tokens"
)

// appFormDomain separates this binding from every other digest a wallet
// credential signs.
const appFormDomain = "privasys-app-form/v1"

// appFormWindow is how long a begun answer may take to finish.
const appFormWindow = 5 * time.Minute

// appFormBinding commits an answer to one sent form (the IdP's own id for it,
// unique even when an app reuses a reference), its app, its reference and
// digest, and one action. Newline-separated fields cannot be confused: none
// of them may contain a newline (ids and digests are shaped, the action is a
// slug).
func appFormBinding(messageID, appID, formID, formDigest, action string, exp int64) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%d",
		appFormDomain, messageID, appID, formID, formDigest, action, exp)))
}

type appFormPending struct {
	session   *webauthn.SessionData
	user      *idpUser
	action    string
	expiresAt time.Time
}

// AppForms serves the two answer endpoints.
type AppForms struct {
	h      *Handler
	msgs   *appmessages.Store
	issuer *tokens.Issuer
	auth   func(w http.ResponseWriter, r *http.Request) string

	mu      sync.Mutex
	pending map[string]*appFormPending // user ‖ 0 ‖ message id
}

// NewAppForms wires the answer endpoints. auth resolves the caller's wallet
// session to the account the form was sent to.
func (h *Handler) NewAppForms(msgs *appmessages.Store, issuer *tokens.Issuer,
	auth func(w http.ResponseWriter, r *http.Request) string) *AppForms {
	return &AppForms{h: h, msgs: msgs, issuer: issuer, auth: auth, pending: map[string]*appFormPending{}}
}

func pendingKey(userID, id string) string { return userID + "\x00" + id }

// HandleBegin serves POST /wallet/app-forms/{id}/begin {action}.
func (a *AppForms) HandleBegin(w http.ResponseWriter, r *http.Request) {
	userID := a.auth(w, r)
	if userID == "" {
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body) != nil || body.Action == "" {
		errorJSON(w, http.StatusBadRequest, "action is required")
		return
	}
	id := r.PathValue("id")
	m, ok := a.msgs.Get(userID, id)
	if !ok || m.Type != appmessages.FormType {
		errorJSON(w, http.StatusNotFound, "no such form, or it was already answered")
		return
	}
	if !slices.Contains(m.Actions, body.Action) {
		errorJSON(w, http.StatusBadRequest, "the form does not offer that action")
		return
	}
	creds, err := a.h.loadCredentials(userID)
	if err != nil || len(creds) == 0 {
		errorJSON(w, http.StatusConflict, "no passkey for this identity")
		return
	}
	user := &idpUser{ID: []byte(userID), Name: userID, Credentials: creds}
	options, session, err := a.h.webAuthn.BeginLogin(user)
	if err != nil {
		log.Printf("fido2/app-form: begin login: %v", err)
		errorJSON(w, http.StatusInternalServerError, "could not begin")
		return
	}
	exp := time.Now().Add(appFormWindow)
	binding := appFormBinding(id, m.AppID, m.FormID, m.FormDigest, body.Action, exp.Unix())
	options.Response.Challenge = protocol.URLEncodedBase64(binding[:])
	session.Challenge = base64.RawURLEncoding.EncodeToString(binding[:])

	a.mu.Lock()
	a.sweepLocked()
	// One begun answer per form at a time: a second begin replaces the first,
	// so only the action the holder tapped last can complete.
	a.pending[pendingKey(userID, id)] = &appFormPending{session: session, user: user, action: body.Action, expiresAt: exp}
	a.mu.Unlock()

	writeJSON(w, map[string]any{
		"options":     options,
		"app_id":      m.AppID,
		"form_id":     m.FormID,
		"form_digest": m.FormDigest,
		"action":      body.Action,
		"expires_at":  exp.Unix(),
	})
}

// HandleAnswer serves POST /wallet/app-forms/{id}/answer {action, assertion}.
func (a *AppForms) HandleAnswer(w http.ResponseWriter, r *http.Request) {
	userID := a.auth(w, r)
	if userID == "" {
		return
	}
	var body struct {
		Action    string          `json:"action"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body) != nil || body.Action == "" || len(body.Assertion) == 0 {
		errorJSON(w, http.StatusBadRequest, "action and assertion are required")
		return
	}
	id := r.PathValue("id")
	key := pendingKey(userID, id)
	a.mu.Lock()
	p := a.pending[key]
	delete(a.pending, key) // one try per begin
	a.mu.Unlock()
	if p == nil || time.Now().After(p.expiresAt) || p.action != body.Action {
		errorJSON(w, http.StatusBadRequest, "begin again: this answer was not started, or has lapsed")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body.Assertion))
	if err != nil {
		errorJSON(w, http.StatusBadRequest, "invalid assertion")
		return
	}
	if _, err := a.h.webAuthn.ValidateLogin(p.user, *p.session, parsed); err != nil {
		log.Printf("fido2/app-form: assertion refused: %v", err)
		errorJSON(w, http.StatusUnauthorized, "the passkey signature did not verify")
		return
	}
	// Verified. Taking the form is the single-use gate: of two answers racing
	// for one form, exactly one gets it.
	m, ok := a.msgs.Take(userID, id)
	if !ok || m.Type != appmessages.FormType || !slices.Contains(m.Actions, body.Action) {
		errorJSON(w, http.StatusConflict, "the form was already answered or has expired")
		return
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	answer, err := a.issuer.IssueAppFormAnswer(tokens.AppFormAnswerClaims{
		Subject: m.AppSub, AppID: m.AppID, FormID: m.FormID, FormDigest: m.FormDigest,
		Action: body.Action, JTI: base64.RawURLEncoding.EncodeToString(jti),
	})
	if err != nil {
		log.Printf("fido2/app-form: sign answer: %v", err)
		errorJSON(w, http.StatusInternalServerError, "could not sign the answer")
		return
	}
	log.Printf("fido2/app-form: answered (app %s, action %s)", m.AppID, body.Action)
	writeJSON(w, map[string]any{
		"answer":            answer,
		"app_id":            m.AppID,
		"app_platform_host": m.PlatformHost,
		"form_id":           m.FormID,
		"action":            body.Action,
	})
}

func (a *AppForms) sweepLocked() {
	now := time.Now()
	for k, p := range a.pending {
		if now.After(p.expiresAt) {
			delete(a.pending, k)
		}
	}
}
