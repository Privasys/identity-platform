// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package accountdeletion deletes a Privasys account, 7 days after the holder
// asks.
//
// The IdP keeps no link between a person's identities, or between an identity
// and the main account, and this package adds none. A deletion is a set of
// independent marks, one per user_id:
//
//   - the page (signed in as the person's privasys.id identity) asks for a
//     deletion and gets a one-time confirm link that opens the wallet;
//   - the wallet, after a fresh passkey ceremony on the main account, confirms
//     it: the main account and the requesting identity are marked, and the
//     control plane is told;
//   - the wallet then marks every other identity it holds, each with its own
//     request signed by that identity's recovery key.
//
// Each mark falls due on its own; its user_id's data is deleted and each of
// its passkeys leaves a tombstone. Cancelling is done by the wallet the same
// way. Notices go to the main account's phones by push only: the IdP holds no
// email address.
package accountdeletion

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/push"
	"github.com/Privasys/idp/internal/store"
)

// Wait is how long a deletion waits, always.
const Wait = 7 * 24 * time.Hour

// freshSessionAge is how recent the wallet's passkey ceremony must be to
// confirm a deletion.
const freshSessionAge = 5 * time.Minute

// requestTTL is how long a confirm link is valid.
const requestTTL = 10 * time.Minute

// MessageDomain separates the identity signature over a deletion mark.
const MessageDomain = "privasys-account-deletion/v1"

// Message is the bytes an identity's recovery key signs to schedule or cancel
// its deletion: domain 0 user_id 0 challenge 0 action 0 delete_at.
func Message(userID string, challenge []byte, action, deleteAt string) []byte {
	msg := make([]byte, 0, len(MessageDomain)+len(userID)+len(challenge)+len(action)+len(deleteAt)+4)
	msg = append(msg, MessageDomain...)
	msg = append(msg, 0)
	msg = append(msg, userID...)
	msg = append(msg, 0)
	msg = append(msg, challenge...)
	msg = append(msg, 0)
	msg = append(msg, action...)
	msg = append(msg, 0)
	return append(msg, deleteAt...)
}

// FormatTime is how delete_at is written everywhere (and signed): RFC 3339,
// UTC, seconds.
func FormatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// ControlPlane is what the deletion needs from the control plane, about the
// account keyed by the person's platform subject.
type ControlPlane interface {
	// Check lists what blocks a deletion (apps, volumes, vaults, sole
	// ownership of an organisation) and the billing row.
	Check(ctx context.Context, sub string) (*CheckResult, error)
	// Event tells it a deletion was scheduled, cancelled or completed.
	Event(ctx context.Context, kind, sub string, deleteAt time.Time) error
}

// CheckResult is the control plane's answer for one person.
type CheckResult struct {
	Blockers []Blocker `json:"blockers"`
	Billing  *Billing  `json:"billing,omitempty"`
}

// Blocker is something the person must delete or hand over first.
type Blocker struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
	Label string `json:"label"`
}

// Billing is the billing row of the deletion page.
type Billing struct {
	HoldsBalance bool   `json:"holds_balance"`
	PageURL      string `json:"page_url"`
}

// Deps wires the package to the rest of the IdP.
type Deps struct {
	DB *store.DB
	// AuthBearer resolves a wallet session or an access token to the account
	// (writes the error itself and returns "" on failure).
	AuthBearer func(w http.ResponseWriter, r *http.Request) string
	// FreshWalletSession resolves a wallet session token opened less than
	// maxAge ago.
	FreshWalletSession func(token string, maxAge time.Duration) (string, bool)
	// VerifyIdentity checks a recovery-key signature for userID over a
	// challenge from /recovery/identity/begin (writes 400/403 itself).
	VerifyIdentity func(w http.ResponseWriter, userID, challenge, signature string, msg func([]byte) []byte) bool
	// PlatformSubject is the subject the control plane knows a user_id by.
	PlatformSubject func(userID string) string
	// RevokeSpend withdraws every spend consent of a user_id (so the platform
	// learns its ledger handles are dead).
	RevokeSpend func(userID string)
	// EndWalletSessions ends the wallet sessions opened by these passkeys.
	EndWalletSessions func(credentialIDs []string)
	// RevokeSessions ends every web session of a user_id.
	RevokeSessions func(userID string)
	// TombstoneKey keys the credential tombstones.
	TombstoneKey []byte
	ControlPlane ControlPlane
	// PageURL is the deletion page (https://privasys.id/account/delete).
	PageURL string
	// ConfirmURL is the wallet's confirm link base.
	ConfirmURL string
	// Push sends one notice to a phone; nil sends nothing (tests).
	Push func(ctx context.Context, userID string, m push.Message) error
	Now  func() time.Time
}

// Service is the deletion API and its sweeper.
type Service struct {
	d Deps

	mu       sync.Mutex
	requests map[string]*request
}

type request struct {
	userID    string // the privasys.id identity that asked
	expiresAt time.Time
	confirmed bool
	deleteAt  time.Time
}

// New returns the service.
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{d: d, requests: map[string]*request{}}
}

// --- handlers ---

type stateResponse struct {
	State    string `json:"state"`
	DeleteAt string `json:"delete_at,omitempty"`
	PageURL  string `json:"page_url,omitempty"`
}

// HandleGet answers GET /account-deletion: whether the caller is marked, and
// when. Only that (the banner shows the countdown and the link).
func (s *Service) HandleGet(w http.ResponseWriter, r *http.Request) {
	userID := s.d.AuthBearer(w, r)
	if userID == "" {
		return
	}
	d, err := s.d.DB.GetAccountDeletion(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if d == nil {
		writeJSON(w, http.StatusOK, stateResponse{State: "none"})
		return
	}
	writeJSON(w, http.StatusOK, stateResponse{State: "pending", DeleteAt: FormatTime(d.DeleteAt), PageURL: s.d.PageURL})
}

// HandleCheck answers GET /account-deletion/check for the page: what blocks a
// deletion, and the billing row, from the control plane.
func (s *Service) HandleCheck(w http.ResponseWriter, r *http.Request) {
	userID := s.d.AuthBearer(w, r)
	if userID == "" {
		return
	}
	res, err := s.check(r.Context(), userID)
	if err != nil {
		log.Printf("[account-deletion] control plane check: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not reach the control plane"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Service) check(ctx context.Context, userID string) (*CheckResult, error) {
	if s.d.ControlPlane == nil {
		return &CheckResult{}, nil
	}
	return s.d.ControlPlane.Check(ctx, s.d.PlatformSubject(userID))
}

// HandleRequest answers POST /account-deletion/request from the page: a
// one-time confirm link that opens the wallet. Refused while something
// blocks the deletion.
func (s *Service) HandleRequest(w http.ResponseWriter, r *http.Request) {
	userID := s.d.AuthBearer(w, r)
	if userID == "" {
		return
	}
	if d, _ := s.d.DB.GetAccountDeletion(userID); d != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "already_pending", "delete_at": FormatTime(d.DeleteAt)})
		return
	}
	res, err := s.check(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not reach the control plane"})
		return
	}
	if len(res.Blockers) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "blocked", "blockers": res.Blockers})
		return
	}
	id := randomID()
	now := s.d.Now()
	s.mu.Lock()
	s.sweepRequestsLocked(now)
	s.requests[id] = &request{userID: userID, expiresAt: now.Add(requestTTL)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{
		"request_id":  id,
		"confirm_url": s.d.ConfirmURL + "?r=" + id,
		"expires_at":  FormatTime(now.Add(requestTTL)),
	})
}

// HandleRequestStatus answers GET /account-deletion/request/{id} for the page
// that asked: waiting, or scheduled with its date.
func (s *Service) HandleRequestStatus(w http.ResponseWriter, r *http.Request) {
	userID := s.d.AuthBearer(w, r)
	if userID == "" {
		return
	}
	s.mu.Lock()
	req, ok := s.requests[r.PathValue("id")]
	var out map[string]string
	if ok && req.userID == userID {
		if req.confirmed {
			out = map[string]string{"status": "scheduled", "delete_at": FormatTime(req.deleteAt)}
		} else if s.d.Now().Before(req.expiresAt) {
			out = map[string]string{"status": "waiting"}
		}
	}
	s.mu.Unlock()
	if out == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleConfirm answers POST /account-deletion {request_id} from the wallet,
// with a wallet session on the main account opened under 5 minutes ago. It
// marks the main account and the identity that asked, tells the control
// plane, and notifies the phones.
func (s *Service) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer wallet:")
	if token == r.Header.Get("Authorization") || token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "a wallet session is required"})
		return
	}
	mainID, ok := s.d.FreshWalletSession(token, freshSessionAge)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "confirm with a fresh sign-in"})
		return
	}
	var body struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || body.RequestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request_id is required"})
		return
	}
	now := s.d.Now()
	s.mu.Lock()
	req, ok := s.requests[body.RequestID]
	if ok && (req.confirmed || now.After(req.expiresAt)) {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired request"})
		return
	}
	// Check again: the page may have been left open.
	res, err := s.check(r.Context(), req.userID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not reach the control plane"})
		return
	}
	if len(res.Blockers) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "blocked", "blockers": res.Blockers})
		return
	}
	deleteAt := now.Add(Wait).UTC().Truncate(time.Second)
	if s.d.ControlPlane != nil {
		if err := s.d.ControlPlane.Event(r.Context(), "scheduled", s.d.PlatformSubject(req.userID), deleteAt); err != nil {
			log.Printf("[account-deletion] control plane scheduled: %v", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not reach the control plane"})
			return
		}
	}
	if err := s.d.DB.MarkAccountDeletion(store.AccountDeletion{UserID: mainID, DeleteAt: deleteAt, Main: true}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if err := s.d.DB.MarkAccountDeletion(store.AccountDeletion{UserID: req.userID, DeleteAt: deleteAt, NotifyControlPlane: true}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	s.mu.Lock()
	req.confirmed, req.deleteAt = true, deleteAt
	s.mu.Unlock()
	s.notify(r.Context(), mainID, "account-deletion-scheduled", "Account deletion scheduled",
		fmt.Sprintf("Your Privasys account will be deleted on %s. You can cancel until then.", deleteAt.Format("2 January 2006")))
	log.Printf("[account-deletion] scheduled for %s", FormatTime(deleteAt))
	writeJSON(w, http.StatusOK, stateResponse{State: "pending", DeleteAt: FormatTime(deleteAt), PageURL: s.d.PageURL})
}

// HandleCancel answers DELETE /account-deletion from the wallet (main
// account session): the main account's mark is removed and the phones told.
// The wallet then cancels each identity itself.
func (s *Service) HandleCancel(w http.ResponseWriter, r *http.Request) {
	userID := s.d.AuthBearer(w, r)
	if userID == "" {
		return
	}
	d, err := s.cancel(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if d == nil {
		writeJSON(w, http.StatusOK, stateResponse{State: "none"})
		return
	}
	writeJSON(w, http.StatusOK, stateResponse{State: "none"})
}

// CancelForRecovery removes the main account's mark when a phrase recovery
// brings the account onto a new phone. The wallet then cancels its
// identities.
func (s *Service) CancelForRecovery(userID string) {
	if _, err := s.cancel(context.Background(), userID); err != nil {
		log.Printf("[account-deletion] cancel on recovery: %v", err)
	}
}

func (s *Service) cancel(ctx context.Context, userID string) (*store.AccountDeletion, error) {
	d, err := s.d.DB.GetAccountDeletion(userID)
	if err != nil || d == nil {
		return d, err
	}
	if d.NotifyControlPlane && s.d.ControlPlane != nil {
		if err := s.d.ControlPlane.Event(ctx, "cancelled", s.d.PlatformSubject(userID), d.DeleteAt); err != nil {
			log.Printf("[account-deletion] control plane cancelled: %v", err)
			return nil, errors.New("could not reach the control plane")
		}
	}
	if _, err := s.d.DB.UnmarkAccountDeletion(userID); err != nil {
		return nil, err
	}
	if d.Main {
		s.notify(ctx, userID, "account-deletion-cancelled", "Account deletion cancelled", "Your Privasys account will not be deleted.")
	}
	return d, nil
}

// HandleIdentity answers POST /account-deletion/identity: the wallet marks
// (or unmarks) one identity, signed by that identity's recovery key over
// Message(user_id, challenge, action, delete_at).
func (s *Service) HandleIdentity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    string `json:"user_id"`
		Action    string `json:"action"`
		DeleteAt  string `json:"delete_at"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.UserID == "" ||
		(req.Action != "schedule" && req.Action != "cancel") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id, action (schedule|cancel), challenge and signature are required"})
		return
	}
	var deleteAt time.Time
	if req.Action == "schedule" {
		t, err := time.Parse(time.RFC3339, req.DeleteAt)
		now := s.d.Now()
		if err != nil || t.Before(now.Add(time.Hour)) || t.After(now.Add(Wait+time.Hour)) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "delete_at must be the scheduled date"})
			return
		}
		deleteAt = t
	}
	if !s.d.VerifyIdentity(w, req.UserID, req.Challenge, req.Signature, func(c []byte) []byte {
		return Message(req.UserID, c, req.Action, req.DeleteAt)
	}) {
		return
	}
	if req.Action == "cancel" {
		if _, err := s.cancel(r.Context(), req.UserID); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stateResponse{State: "none"})
		return
	}
	if err := s.d.DB.MarkAccountDeletion(store.AccountDeletion{UserID: req.UserID, DeleteAt: deleteAt}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, stateResponse{State: "pending", DeleteAt: FormatTime(deleteAt)})
}

// HandleTombstone answers GET /account-deletion/tombstone?credential_id=, no
// auth: 410 with the reason when the passkey's account was deleted or its
// phone removed, 404 otherwise. A wallet clears itself only on the 410.
func (s *Service) HandleTombstone(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("credential_id")
	if id == "" || len(id) > 1024 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credential_id is required"})
		return
	}
	if reason := s.d.DB.TombstoneReason(s.d.TombstoneKey, id, s.d.Now()); reason != "" {
		writeJSON(w, http.StatusGone, map[string]string{"error": reason})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown"})
}

// --- sweeper ---

// Run sweeps every interval until ctx ends: reminders a day before, then
// deletions that fell due.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.Sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sweep sends due reminders and deletes due accounts. Safe to repeat: a
// deletion that fails part way is retried on the next sweep.
func (s *Service) Sweep(ctx context.Context) {
	now := s.d.Now()
	if due, err := s.d.DB.DeletionsToRemind(now); err == nil {
		for _, d := range due {
			s.notify(ctx, d.UserID, "account-deletion-reminder", "Your account is deleted tomorrow",
				"Your Privasys account will be deleted tomorrow. Save what you need, or cancel in Privasys Wallet.")
			_ = s.d.DB.SetDeletionReminded(d.UserID)
		}
	}
	due, err := s.d.DB.DueAccountDeletions(now)
	if err != nil {
		log.Printf("[account-deletion] list due: %v", err)
		return
	}
	for _, d := range due {
		if err := s.deleteOne(ctx, d); err != nil {
			log.Printf("[account-deletion] delete (will retry): %v", err)
		}
	}
	_ = s.d.DB.CleanupTombstones(now)
}

func (s *Service) deleteOne(ctx context.Context, d store.AccountDeletion) error {
	// The control plane closes the account before the identity behind it
	// goes; until it answers, the identity stays and the sweep retries.
	if d.NotifyControlPlane && s.d.ControlPlane != nil {
		if err := s.d.ControlPlane.Event(ctx, "deleted", s.d.PlatformSubject(d.UserID), d.DeleteAt); err != nil {
			return fmt.Errorf("control plane: %w", err)
		}
	}
	// Tell the phones before their push targets go. The push alone never
	// clears a wallet: it checks the tombstone first.
	if d.Main {
		s.notify(ctx, d.UserID, "account-deleted", "Account deleted", "Your Privasys account has been deleted.")
	}
	if s.d.RevokeSpend != nil {
		s.d.RevokeSpend(d.UserID)
	}
	creds, err := s.d.DB.CredentialIDs(d.UserID)
	if err != nil {
		return err
	}
	if err := s.d.DB.AddTombstones(s.d.TombstoneKey, creds, store.TombstoneAccountDeleted, s.d.Now()); err != nil {
		return err
	}
	if s.d.RevokeSessions != nil {
		s.d.RevokeSessions(d.UserID)
	}
	if err := s.d.DB.DeleteUserData(d.UserID); err != nil {
		return err
	}
	if s.d.EndWalletSessions != nil {
		s.d.EndWalletSessions(creds)
	}
	return nil
}

// --- helpers ---

// notify pushes a notice to every phone of the main account. Data carries the
// type only; the wallet reads the details over TLS.
func (s *Service) notify(ctx context.Context, userID, typ, title, body string) {
	if s.d.Push == nil {
		return
	}
	for _, t := range s.d.DB.GetPushTargets(userID) {
		m := push.Message{Token: t.Token, Title: title, Body: body, Data: map[string]string{"type": typ}}
		if err := s.d.Push(ctx, userID, m); err != nil {
			log.Printf("[account-deletion] push %s: %v", typ, err)
		}
	}
}

func (s *Service) sweepRequestsLocked(now time.Time) {
	for k, v := range s.requests {
		if now.After(v.expiresAt.Add(time.Hour)) {
			delete(s.requests, k)
		}
	}
}

func randomID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// --- control plane client ---

// MgmtControlPlane talks to the management service's internal API with the
// IdP's static bearer.
type MgmtControlPlane struct {
	URL    string
	Token  string
	Client *http.Client
}

func (c *MgmtControlPlane) post(ctx context.Context, path string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	cl := c.Client
	if cl == nil {
		cl = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(out)
	}
	return nil
}

// Check implements ControlPlane.
func (c *MgmtControlPlane) Check(ctx context.Context, sub string) (*CheckResult, error) {
	var out CheckResult
	err := c.post(ctx, "/api/v1/internal/account-deletion/check", map[string]string{"sub": sub}, &out)
	return &out, err
}

// Event implements ControlPlane.
func (c *MgmtControlPlane) Event(ctx context.Context, kind, sub string, deleteAt time.Time) error {
	return c.post(ctx, "/api/v1/internal/account-deletion/event", map[string]string{
		"event": kind, "sub": sub, "delete_at": FormatTime(deleteAt),
	}, nil)
}
