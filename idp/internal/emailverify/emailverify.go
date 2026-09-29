// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package emailverify proves that a holder can read mail at an address.
//
// The wallet asks for a code, the IdP mails one to the address, and the holder
// types it back. What comes out is a signed receipt: this account proved this
// address, at this time, by reading a code sent to it. The wallet keeps the
// receipt; the IdP keeps nothing.
//
// Keeping nothing is the point. privasys.id does not store the holder's
// attributes, so it must not end up with a table of who owns which address.
// The address is held only while a code is outstanding, in memory, for as long
// as the code is valid, and is gone the moment it is used or expires. Logs
// never carry it either.
//
// What this proves is control of the mailbox now, which is all any email check
// anywhere proves. It says nothing about who owns the account behind it.
package emailverify

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

const (
	// codeTTL bounds how long a mailed code is worth typing. Long enough for
	// mail to arrive and the holder to switch apps, short enough that a code
	// read off a screen later is useless.
	codeTTL = 15 * time.Minute
	// resendAfter stops a tap-happy holder, or a caller in a loop, from
	// mailing the same address repeatedly.
	resendAfter = 60 * time.Second
	// maxAttempts on one code. A 6-digit code has a million values, so five
	// guesses is nowhere near enough to find one, and the code dies on the
	// fifth wrong answer rather than waiting out its TTL.
	maxAttempts = 5
	// maxPending caps the outstanding codes one account can have, so this
	// cannot be driven into unbounded memory, or used to mail a list of
	// addresses.
	maxPending = 5
	// maxEmailLen is the practical limit on an address (RFC 5321).
	maxEmailLen = 254
)

// Mailer is the part of the IdP's mailer this package needs. The recovery
// Mailer satisfies it.
type Mailer interface {
	Enabled() bool
	Send(to, subject, body string) error
}

// Authenticate resolves the caller to a user id, or writes the error and
// returns "". The IdP's existing bearer check (wallet session or JWT) fits.
type Authenticate func(w http.ResponseWriter, r *http.Request) string

type pending struct {
	codeHash  [32]byte
	attempts  int
	expiresAt time.Time
	sentAt    time.Time
}

// Service holds the outstanding codes and the pieces needed to mail one and
// sign the receipt.
type Service struct {
	mailer Mailer
	issuer *tokens.Issuer
	auth   Authenticate
	now    func() time.Time

	mu      sync.Mutex
	pending map[string]map[string]*pending // user id -> address -> code
}

// New returns a service that sweeps expired codes once a minute.
func New(mailer Mailer, issuer *tokens.Issuer, auth Authenticate) *Service {
	s := newService(mailer, issuer, auth, time.Now)
	go func() {
		for {
			time.Sleep(time.Minute)
			s.sweep()
		}
	}()
	return s
}

func newService(mailer Mailer, issuer *tokens.Issuer, auth Authenticate, now func() time.Time) *Service {
	return &Service{
		mailer:  mailer,
		issuer:  issuer,
		auth:    auth,
		now:     now,
		pending: make(map[string]map[string]*pending),
	}
}

// normaliseEmail lowercases and trims an address, and reports whether it is
// one address in a shape worth mailing. Nothing clever: no domain rules, no
// existence check, just enough that a malformed value fails here rather than
// at the mail API.
func normaliseEmail(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > maxEmailLen {
		return "", false
	}
	addr, err := mail.ParseAddress(trimmed)
	if err != nil || addr.Name != "" {
		return "", false
	}
	// A display name, a second address or anything else that turns one header
	// into two is refused above and here: ParseAddress accepts "A <a@b.c>".
	at := strings.LastIndex(addr.Address, "@")
	if at <= 0 || at == len(addr.Address)-1 || strings.ContainsAny(addr.Address, " \t\r\n,;") {
		return "", false
	}
	return strings.ToLower(addr.Address), true
}

// newCode returns a 6-digit code, uniformly drawn.
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// HandleBegin serves POST /wallet/email/verify/begin {"email": "..."}.
//
// Answers 200 with when another code may be asked for, 400 on a malformed
// address, 429 when one was just sent, and 503 when this server cannot send
// mail at all. It never reveals anything about the address: any address the
// holder can type is one they may ask us to mail.
func (s *Service) HandleBegin(w http.ResponseWriter, r *http.Request) {
	userID := s.auth(w, r)
	if userID == "" {
		return
	}
	if !s.mailer.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "this server cannot send mail")
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	email, ok := normaliseEmail(req.Email)
	if !ok {
		writeError(w, http.StatusBadRequest, "that is not an email address")
		return
	}

	code, err := newCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start the check")
		return
	}

	now := s.now()
	s.mu.Lock()
	mine := s.pending[userID]
	if mine == nil {
		mine = make(map[string]*pending)
		s.pending[userID] = mine
	}
	if cur, exists := mine[email]; exists && now.Sub(cur.sentAt) < resendAfter {
		wait := int((resendAfter - now.Sub(cur.sentAt)).Seconds()) + 1
		s.mu.Unlock()
		w.Header().Set("Retry-After", fmt.Sprintf("%d", wait))
		writeError(w, http.StatusTooManyRequests, "a code was just sent; wait before asking for another")
		return
	}
	if _, exists := mine[email]; !exists && len(mine) >= maxPending {
		s.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too many checks at once; finish or wait for one to expire")
		return
	}
	mine[email] = &pending{
		codeHash:  sha256.Sum256([]byte(code)),
		expiresAt: now.Add(codeTTL),
		sentAt:    now,
	}
	s.mu.Unlock()

	subject := "Privasys verification code"
	body := fmt.Sprintf(
		"Your Privasys verification code is:\n\n"+
			"    %s\n\n"+
			"Type it into your wallet to confirm this address is yours. "+
			"The code stops working in %d minutes.\n\n"+
			"If you did not ask for this, nothing has happened to your account "+
			"and you can ignore this message. Whoever asked cannot see it.\n",
		code, int(codeTTL.Minutes()),
	)
	if err := s.mailer.Send(email, subject, body); err != nil {
		// The address is not logged: it is the holder's, and this server is
		// meant to forget it.
		log.Printf("emailverify: send failed: %v", err)
		s.forget(userID, email)
		writeError(w, http.StatusBadGateway, "the code could not be sent")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"expires_at":   now.Add(codeTTL).Unix(),
		"resend_after": int(resendAfter.Seconds()),
		"code_length":  6,
		"max_attempts": maxAttempts,
	})
}

// HandleComplete serves POST /wallet/email/verify/complete
// {"email": "...", "code": "123456"}.
//
// On the right code it answers 200 with the signed receipt and forgets the
// address. On a wrong one, 400 with how many tries are left; the code dies on
// the last of them.
func (s *Service) HandleComplete(w http.ResponseWriter, r *http.Request) {
	userID := s.auth(w, r)
	if userID == "" {
		return
	}
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	email, ok := normaliseEmail(req.Email)
	code := strings.TrimSpace(req.Code)
	if !ok || code == "" {
		writeError(w, http.StatusBadRequest, "an address and a code are required")
		return
	}

	now := s.now()
	s.mu.Lock()
	entry := s.pending[userID][email]
	if entry == nil || now.After(entry.expiresAt) {
		delete(s.pending[userID], email)
		s.mu.Unlock()
		writeError(w, http.StatusGone, "that code has expired; ask for a new one")
		return
	}
	got := sha256.Sum256([]byte(code))
	if subtle.ConstantTimeCompare(got[:], entry.codeHash[:]) != 1 {
		entry.attempts++
		left := maxAttempts - entry.attempts
		if left <= 0 {
			delete(s.pending[userID], email)
		}
		s.mu.Unlock()
		if left <= 0 {
			writeError(w, http.StatusGone, "too many wrong codes; ask for a new one")
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":         "that code is not right",
			"attempts_left": left,
		})
		return
	}
	// Right code: single use, and the address goes with it.
	delete(s.pending[userID], email)
	if len(s.pending[userID]) == 0 {
		delete(s.pending, userID)
	}
	s.mu.Unlock()

	receipt, err := s.issuer.IssueEmailVerification(tokens.EmailVerificationClaims{
		Subject: userID,
		Email:   email,
		Method:  "email-code",
	})
	if err != nil {
		log.Printf("emailverify: receipt signing failed: %v", err)
		writeError(w, http.StatusInternalServerError, "could not sign the result")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":       email,
		"verified_at": now.Unix(),
		"method":      "email-code",
		"receipt":     receipt,
	})
}

func (s *Service) forget(userID, email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mine := s.pending[userID]; mine != nil {
		delete(mine, email)
		if len(mine) == 0 {
			delete(s.pending, userID)
		}
	}
}

func (s *Service) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for userID, mine := range s.pending {
		for email, e := range mine {
			if now.After(e.expiresAt) {
				delete(mine, email)
			}
		}
		if len(mine) == 0 {
			delete(s.pending, userID)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
