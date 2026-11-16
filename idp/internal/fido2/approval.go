// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

// The holder's answer to an approval (internal/appmessages/approval.go): an
// app asking whether the holder approves one act, at an assurance it names.
//
//  1. begin: the wallet names the approval and the decision. The IdP checks
//     the approval is this holder's and still open, and starts a WebAuthn
//     login with user verification REQUIRED, whose challenge commits to the
//     app, the approval's reference and digest, the act's digest, the
//     decision and the assurance.
//  2. answer: the wallet returns the assertion. The IdP verifies it,
//     including the user-verification flag (the phone's biometric or
//     passcode, not just a tap), takes the approval off the list (one answer,
//     ever), and signs an op-approval token naming the subject the app
//     addressed and the assurance reached.
//
// The wallet posts the token to the app over attested RA-TLS, to the host it
// confirmed the approval with. The app checks the token against this IdP's
// keys, the approval digest against the string it sent, and the act digest
// against the act it is about to commit.

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

// approvalDomain separates this binding from every other digest a wallet
// credential signs.
const approvalDomain = "privasys-approval/v1"

// approvalWindow is how long a begun answer may take to finish.
const approvalWindow = 5 * time.Minute

// approvalBinding commits an answer to one sent approval (the IdP's own id for
// it), its app, its reference and digest, the act's digest, one decision and
// the assurance. None of the fields can hold a newline: ids and digests are
// shaped, the decision and the assurance come from closed lists.
func approvalBinding(messageID, appID, approvalID, approvalDigest, actDigest, decision, assurance string, exp int64) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%d",
		approvalDomain, messageID, appID, approvalID, approvalDigest, actDigest, decision, assurance, exp)))
}

type approvalPending struct {
	session   *webauthn.SessionData
	user      *idpUser
	decision  string
	expiresAt time.Time
}

// Approvals serves the two answer endpoints.
type Approvals struct {
	h      *Handler
	msgs   *appmessages.Store
	issuer *tokens.Issuer
	auth   func(w http.ResponseWriter, r *http.Request) string

	mu      sync.Mutex
	pending map[string]*approvalPending // user ‖ 0 ‖ message id
}

// NewApprovals wires the answer endpoints. auth resolves the caller's wallet
// session to the account the approval was sent to.
func (h *Handler) NewApprovals(msgs *appmessages.Store, issuer *tokens.Issuer,
	auth func(w http.ResponseWriter, r *http.Request) string) *Approvals {
	return &Approvals{h: h, msgs: msgs, issuer: issuer, auth: auth, pending: map[string]*approvalPending{}}
}

// HandleBegin serves POST /wallet/approvals/{id}/begin {decision}.
func (a *Approvals) HandleBegin(w http.ResponseWriter, r *http.Request) {
	userID := a.auth(w, r)
	if userID == "" {
		return
	}
	var body struct {
		Decision string `json:"decision"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body) != nil ||
		!slices.Contains(appmessages.Decisions, body.Decision) {
		errorJSON(w, http.StatusBadRequest, "decision is approve or decline")
		return
	}
	id := r.PathValue("id")
	m, ok := a.msgs.Get(userID, id)
	if !ok || m.Type != appmessages.ApprovalType {
		errorJSON(w, http.StatusNotFound, "no such approval, or it was already answered")
		return
	}
	if m.Assurance != appmessages.AssuranceDevice {
		// gov-presence is refused at notify until it is built; a row of it
		// cannot be answered at a lower assurance than the app asked for.
		errorJSON(w, http.StatusConflict, "this approval needs an assurance this identity provider cannot give yet")
		return
	}
	creds, err := a.h.loadCredentials(userID)
	if err != nil || len(creds) == 0 {
		errorJSON(w, http.StatusConflict, "no passkey for this identity")
		return
	}
	user := &idpUser{ID: []byte(userID), Name: userID, Credentials: creds}
	// The biometric (or the phone's passcode) is the point: a tap alone does
	// not approve an act.
	options, session, err := a.h.webAuthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		log.Printf("fido2/approval: begin login: %v", err)
		errorJSON(w, http.StatusInternalServerError, "could not begin")
		return
	}
	exp := time.Now().Add(approvalWindow)
	if until := time.Unix(m.ExpiresAt, 0); until.Before(exp) {
		exp = until
	}
	binding := approvalBinding(id, m.AppID, m.FormID, m.FormDigest, m.ActDigest, body.Decision, m.Assurance, exp.Unix())
	options.Response.Challenge = protocol.URLEncodedBase64(binding[:])
	session.Challenge = base64.RawURLEncoding.EncodeToString(binding[:])

	a.mu.Lock()
	a.sweepLocked()
	// One begun answer per approval at a time: a second begin replaces the
	// first, so only the decision the holder tapped last can complete.
	a.pending[pendingKey(userID, id)] = &approvalPending{session: session, user: user, decision: body.Decision, expiresAt: exp}
	a.mu.Unlock()

	writeJSON(w, map[string]any{
		"options":         options,
		"app_id":          m.AppID,
		"approval_id":     m.FormID,
		"approval_digest": m.FormDigest,
		"act_digest":      m.ActDigest,
		"assurance":       m.Assurance,
		"decision":        body.Decision,
		"expires_at":      exp.Unix(),
	})
}

// HandleAnswer serves POST /wallet/approvals/{id}/answer {decision, assertion}.
func (a *Approvals) HandleAnswer(w http.ResponseWriter, r *http.Request) {
	userID := a.auth(w, r)
	if userID == "" {
		return
	}
	var body struct {
		Decision  string          `json:"decision"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body) != nil || body.Decision == "" || len(body.Assertion) == 0 {
		errorJSON(w, http.StatusBadRequest, "decision and assertion are required")
		return
	}
	id := r.PathValue("id")
	key := pendingKey(userID, id)
	a.mu.Lock()
	p := a.pending[key]
	delete(a.pending, key) // one try per begin
	a.mu.Unlock()
	if p == nil || time.Now().After(p.expiresAt) || p.decision != body.Decision {
		errorJSON(w, http.StatusBadRequest, "begin again: this answer was not started, or has lapsed")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body.Assertion))
	if err != nil {
		errorJSON(w, http.StatusBadRequest, "invalid assertion")
		return
	}
	// The session asked for user verification, so the library refuses an
	// assertion without the UV flag; checked again here, so the rule does not
	// rest on a library default.
	if !parsed.Response.AuthenticatorData.Flags.UserVerified() {
		errorJSON(w, http.StatusUnauthorized, "the passkey was used without the biometric")
		return
	}
	if _, err := a.h.webAuthn.ValidateLogin(p.user, *p.session, parsed); err != nil {
		log.Printf("fido2/approval: assertion refused: %v", err)
		errorJSON(w, http.StatusUnauthorized, "the passkey signature did not verify")
		return
	}
	// Verified. Taking the approval is the single-use gate.
	m, ok := a.msgs.Take(userID, id)
	if !ok || m.Type != appmessages.ApprovalType {
		errorJSON(w, http.StatusConflict, "the approval was already answered or has expired")
		return
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	token, err := a.issuer.IssueOpApproval(tokens.OpApprovalClaims{
		Subject: m.AppSub, AppID: m.AppID, ApprovalID: m.FormID, ApprovalDigest: m.FormDigest,
		ActDigest: m.ActDigest, Decision: body.Decision,
		ACR: appmessages.AssuranceDevice, AMR: []string{"webauthn"},
		JTI: base64.RawURLEncoding.EncodeToString(jti),
	})
	if err != nil {
		log.Printf("fido2/approval: sign token: %v", err)
		errorJSON(w, http.StatusInternalServerError, "could not sign the answer")
		return
	}
	log.Printf("fido2/approval: answered (app %s, decision %s)", m.AppID, body.Decision)
	writeJSON(w, map[string]any{
		"token":             token,
		"app_id":            m.AppID,
		"app_platform_host": m.PlatformHost,
		"approval_id":       m.FormID,
		"decision":          body.Decision,
	})
}

func (a *Approvals) sweepLocked() {
	now := time.Now()
	for k, p := range a.pending {
		if now.After(p.expiresAt) {
			delete(a.pending, k)
		}
	}
}
