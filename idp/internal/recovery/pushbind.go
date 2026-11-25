// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/push"
)

// A push token is bound to the device that receives its pushes.
//
// Registering a push token used to take the caller's word that the token was
// its own device's: an identity that knew another device's token could attach
// itself to that device, have its pushes land there, and be counted among the
// holder's "other phones". Signing the registration does not close that by
// itself, because whoever registers first would choose the key.
//
// What only the real device can do is receive a push sent to the token. So a
// token is bound by a challenge sent through the push channel: privasys.id
// pushes a nonce to the token, and the wallet returns it signed with a key it
// made for the purpose (bind_pub). That key is then the token's, and a
// different key is only taken after a new challenge.
//
// The answer binds no registration by itself. Each identity on the phone is
// bound by registering the token with a signature, under that key, over its
// own subject. A key is public, so an identity that merely names a device's
// key gains nothing: the device never signs for a subject it does not hold.
//
// Until a token is bound it still receives its own identity's pushes, as
// before. What reads across identities or devices (the icon's count, clearing
// a notification on the holder's other phones) uses bound rows only.

const (
	pushBindType       = "push-bind"
	pushBindTTL        = 5 * time.Minute
	pushBindPerMinute  = 1
	pushBindPerDay     = 20
	pushRegisterWindow = 5 * time.Minute
)

type pushBindChallenge struct {
	nonce   string
	expires time.Time
}

// pushBindState holds the open challenges and how often each token was sent
// one. In memory: a challenge is worthless after five minutes, and a restart
// only makes a wallet ask again.
type pushBindState struct {
	mu         sync.Mutex
	challenges map[string]pushBindChallenge // token + "\x00" + bind_pub
	sent       map[string][]time.Time       // token -> challenges sent in the last day
	now        func() time.Time
	send       func(ctx context.Context, db push.Store, userID string, m push.Message) error
}

var pushBinds = &pushBindState{
	challenges: map[string]pushBindChallenge{},
	sent:       map[string][]time.Time{},
	now:        time.Now,
	send:       push.Notify,
}

// allow reports whether one more challenge may go to token, and records it.
// Anyone who knows a token could otherwise use registration to send that
// device silent pushes without end.
func (s *pushBindState) allow(token string) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.sent[token][:0]
	for _, t := range s.sent[token] {
		if now.Sub(t) < 24*time.Hour {
			kept = append(kept, t)
		}
	}
	recent := 0
	for _, t := range kept {
		if now.Sub(t) < time.Minute {
			recent++
		}
	}
	if recent >= pushBindPerMinute || len(kept) >= pushBindPerDay {
		s.sent[token] = kept
		return false
	}
	s.sent[token] = append(kept, now)
	return true
}

// open makes a challenge for (token, bindPub) and returns its nonce.
func (s *pushBindState) open(token, bindPub string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.challenges {
		if now.After(c.expires) {
			delete(s.challenges, k)
		}
	}
	s.challenges[token+"\x00"+bindPub] = pushBindChallenge{nonce: nonce, expires: now.Add(pushBindTTL)}
	return nonce, nil
}

// take spends the challenge for (token, bindPub) when nonce is the one sent.
// Single use: a wrong answer spends it too.
func (s *pushBindState) take(token, bindPub, nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := token + "\x00" + bindPub
	c, ok := s.challenges[key]
	delete(s.challenges, key)
	return ok && !s.now().After(c.expires) && subtle.ConstantTimeCompare([]byte(c.nonce), []byte(nonce)) == 1
}

// pushBindKey decodes a wallet's binding key: 32 bytes, base64url.
func pushBindKey(s string) (ed25519.PublicKey, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

func pushBindSig(s string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return raw, err == nil && len(raw) == ed25519.SignatureSize
}

// pushRegisterText is what a wallet signs to bind one of its identities to a
// token whose key it has proven.
func pushRegisterText(token, subject string, issuedAt int64) []byte {
	return []byte("privasys-push-register/v1\n" + token + "\n" + subject + "\n" + strconv.FormatInt(issuedAt, 10))
}

// pushBindText is what a wallet signs to answer a challenge.
func pushBindText(token, nonce string) []byte {
	return []byte("privasys-push-bind/v1\n" + token + "\n" + nonce)
}

// bindRegistration settles whether userID's registration of token is bound,
// and sends a challenge when it is not yet. It returns whether the row is
// bound now. A wallet that sends no binding key is registered as before,
// unbound.
func (h *Handler) bindRegistration(userID, token, bindPub, sig string, issuedAt int64) bool {
	key, ok := pushBindKey(bindPub)
	if !ok {
		_ = h.db.SetPushBinding(userID, token, "", false)
		return false
	}
	// The token's proven key: a signature by it over this subject binds the
	// row, and nothing else does. No challenge is sent for a key that is
	// already proven, so naming a device's key cannot be used to push to it.
	if recorded := h.db.PushTokenBindKey(token); recorded != "" && recorded == bindPub {
		raw, okSig := pushBindSig(sig)
		age := pushBinds.now().Sub(time.Unix(issuedAt, 0))
		bound := okSig && age > -pushRegisterWindow && age < pushRegisterWindow &&
			ed25519.Verify(key, pushRegisterText(token, userID, issuedAt), raw)
		if err := h.db.SetPushBinding(userID, token, bindPub, bound); err != nil {
			log.Printf("[push-bind] recording a binding: %v", err)
			return false
		}
		return bound
	}
	// Not this token's key yet: the row waits, and the device is challenged.
	if err := h.db.SetPushBinding(userID, token, bindPub, false); err != nil {
		log.Printf("[push-bind] recording a pending binding: %v", err)
		return false
	}
	if !pushBinds.allow(token) {
		log.Printf("[push-bind] challenge rate limit reached for a token")
		return false
	}
	nonce, err := pushBinds.open(token, bindPub)
	if err != nil {
		log.Printf("[push-bind] challenge: %v", err)
		return false
	}
	go func() {
		if err := pushBinds.send(context.Background(), h.db, userID, push.Message{
			Token:      token,
			Background: true,
			Data:       map[string]string{"type": pushBindType, "nonce": nonce, "bind_pub": bindPub},
		}); err != nil {
			log.Printf("[push-bind] sending a challenge: %v", err)
		}
	}()
	return false
}

// HandleBindPushToken takes a wallet's answer to a binding challenge.
//
// POST /push-token/bind {"push_token", "bind_pub", "nonce", "sig"}
//
// No bearer: the nonce reached only the device that receives the token's
// pushes, and the signature shows the answer comes from the holder of the key
// the challenge was opened for. Together they are the proof. The answer makes
// that key the token's; the wallet then registers each identity again, signed.
func (h *Handler) HandleBindPushToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PushToken string `json:"push_token"`
		BindPub   string `json:"bind_pub"`
		Nonce     string `json:"nonce"`
		Sig       string `json:"sig"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil ||
		req.PushToken == "" || len(req.PushToken) > 256 || req.Nonce == "" || len(req.Nonce) > 128 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "push_token, bind_pub, nonce and sig are required"})
		return
	}
	key, okKey := pushBindKey(req.BindPub)
	sig, okSig := pushBindSig(req.Sig)
	if !okKey || !okSig {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bind_pub and sig are not well formed"})
		return
	}
	// The same answer whether the challenge was unknown, spent, expired or the
	// signature wrong: nothing here tells a guesser which.
	if !pushBinds.take(req.PushToken, req.BindPub, req.Nonce) ||
		!ed25519.Verify(key, pushBindText(req.PushToken, req.Nonce), sig) {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "not bound"})
		return
	}
	if err := h.db.BindPushToken(req.PushToken, req.BindPub); err != nil {
		log.Printf("[push-bind] binding: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]string{"status": "bound"})
}
