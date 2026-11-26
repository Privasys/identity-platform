// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package recovery

import (
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
// token is bound by a challenge that travels with a push: a nonce the wallet
// returns signed with a key it made for the purpose (bind_pub). That key is
// then the token's, and a different key is only taken after a new challenge.
//
// The nonce rides in the data of the VISIBLE pushes privasys.id sends anyway (a
// sign-in request, an approval), never in a push of its own. A silent push
// sent only to carry it did not reach the wallet's code on iOS, which decides
// for itself whether to wake an app for one; a notification the holder sees
// does. It also means nobody can cause a push to a device by registering its
// token: no push is ever sent for the binding's sake.
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
	// pushBindTTL is how long a challenge can be answered: the longest a
	// request lives, since the holder may open its notification late.
	pushBindTTL        = 15 * time.Minute
	pushRegisterWindow = 5 * time.Minute
)

type pushBindChallenge struct {
	nonce   string
	expires time.Time
}

// pushBindState holds the open challenges. In memory: a challenge is
// worthless once it has lapsed, and a restart only means the next visible
// push carries a new one.
type pushBindState struct {
	mu         sync.Mutex
	challenges map[string]pushBindChallenge // token + "\x00" + bind_pub
	now        func() time.Time
}

var pushBinds = &pushBindState{
	challenges: map[string]pushBindChallenge{},
	now:        time.Now,
}

// open returns the challenge for (token, bindPub): the one already open, so
// that every push sent while it lives carries the same nonce and any of them
// can be answered, or a new one.
func (s *pushBindState) open(token, bindPub string) (string, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.challenges {
		if now.After(c.expires) {
			delete(s.challenges, k)
		}
	}
	key := token + "\x00" + bindPub
	if c, ok := s.challenges[key]; ok {
		return c.nonce, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	s.challenges[key] = pushBindChallenge{nonce: nonce, expires: now.Add(pushBindTTL)}
	return nonce, nil
}

// take spends the challenge for (token, bindPub) when nonce is the one sent.
// Single use: a wrong answer spends it too. The second result says why it was
// refused, for the log only: the caller is told the same thing in every case.
func (s *pushBindState) take(token, bindPub, nonce string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := token + "\x00" + bindPub
	c, ok := s.challenges[key]
	delete(s.challenges, key)
	switch {
	case !ok:
		return false, "no challenge is open for this device and key"
	case s.now().After(c.expires):
		return false, "the challenge had expired"
	case subtle.ConstantTimeCompare([]byte(c.nonce), []byte(nonce)) != 1:
		return false, "the nonce is not the one sent"
	}
	return true, ""
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
		// Neither the device nor the identity is named: only what happened.
		if bound {
			log.Printf("[push-bind] a registration was bound by its signature")
		} else {
			log.Printf("[push-bind] a registration under a proven key was not bound (signature present=%t, in window=%t)", okSig, age > -pushRegisterWindow && age < pushRegisterWindow)
		}
		if err := h.db.SetPushBinding(userID, token, bindPub, bound); err != nil {
			log.Printf("[push-bind] recording a binding: %v", err)
			return false
		}
		return bound
	}
	// Not this token's key yet: the row waits. The challenge travels with the
	// next push the holder sees (BindChallengeFor); none is sent from here.
	if err := h.db.SetPushBinding(userID, token, bindPub, false); err != nil {
		log.Printf("[push-bind] recording a pending binding: %v", err)
	}
	return false
}

// BindChallengeFor is the challenge to carry in a visible push that is about
// to be sent to token for userID, or "" when there is none to carry.
//
// One is carried only while that identity's registration of the token names a
// binding key that is not yet the token's proven key. A registration that
// names no key (an older wallet) carries none, and neither does one whose key
// is already proven: what it lacks then is its own signature, which a push
// cannot supply.
func (h *Handler) BindChallengeFor(userID, token string) (nonce, bindPub string) {
	if userID == "" || token == "" {
		return "", ""
	}
	bindPub, bound := h.db.PushBinding(userID, token)
	if bound || bindPub == "" || h.db.PushTokenBindKey(token) == bindPub {
		return "", ""
	}
	if _, ok := pushBindKey(bindPub); !ok {
		return "", ""
	}
	nonce, err := pushBinds.open(token, bindPub)
	if err != nil {
		log.Printf("[push-bind] challenge: %v", err)
		return "", ""
	}
	return nonce, bindPub
}

// HandleBindPushToken takes a wallet's answer to a binding challenge.
//
// POST /push-token/bind {"push_token", "bind_pub", "nonce", "sig"}
//
// No bearer: the nonce travelled only in pushes to the token, so it reached
// only the device that receives them, and the signature shows the answer comes from the holder of the key
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
	taken, why := pushBinds.take(req.PushToken, req.BindPub, req.Nonce)
	if taken && !ed25519.Verify(key, pushBindText(req.PushToken, req.Nonce), sig) {
		taken, why = false, "the signature is not by the key the challenge was opened for"
	}
	if !taken {
		// The reason stays here; the caller learns nothing from it.
		log.Printf("[push-bind] an answer was refused: %s", why)
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "not bound"})
		return
	}
	if err := h.db.BindPushToken(req.PushToken, req.BindPub); err != nil {
		log.Printf("[push-bind] binding: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	log.Printf("[push-bind] an answer was accepted: the device's key is proven")
	writeJSONStatus(w, http.StatusOK, map[string]string{"status": "bound"})
}
