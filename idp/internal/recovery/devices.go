// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/idp/internal/push"
	"github.com/Privasys/idp/internal/store"
)

// Devices: a holder with several phones.
//
// Every phone of a holder holds the same seed, so the same identities, and its
// own passkey on each. Adding a phone:
//
//  1. the new phone opens a pairing slot here and shows a QR code naming it and
//     the new phone's ephemeral X25519 key;
//  2. the old phone scans it, the holder confirms, and the old phone puts into
//     the slot the wallet's secrets sealed to that key, with an enrolment
//     ticket for the main account it minted with its own session;
//  3. the new phone reads the slot (which empties it), redeems the ticket to
//     register a passkey on the main account, and enrols on each identity by
//     that identity's recovery key.
//
// None of it removes the other phones' passkeys: that is what distinguishes an
// enrolment from a recovery. Revoking a phone removes its passkeys on the main
// account (with a session) and on each identity (with that identity's recovery
// key, which is rotated in the same request to one derived from a secret the
// revoked phone never received).
//
// The server sees ciphertext in the slot and the relay, device tags that are
// unrelated from one identity to the next, and, when a phone is added or
// revoked, a burst of requests on the holder's identities at once: the holder
// asked for it, and the push targets already relate those identities.

const (
	enrolTicketTTL = 10 * time.Minute
	pairingTTL     = 10 * time.Minute
	// maxPairingBlob bounds the sealed transfer: the secrets are tiny, the
	// profile is most of it.
	maxPairingBlob = 4 << 20
	maxRelayBlob   = 1 << 20
	// maxRelayTotal bounds the memory every waiting update takes together.
	maxRelayTotal    = 128 << 20
	maxRelayPerPhone = 50
	relayTTL         = 15 * time.Minute
	// maxDevices is how many phones one holder may have.
	maxDevices = 5

	identityEnrolDomain  = "privasys-identity-enrol/v1"
	identityRevokeDomain = "privasys-identity-revoke/v1"

	pairingsPerIP = 30
	enrolsPerIP   = 30
)

// IdentityEnrolMessage is the byte string an identity's recovery key signs to
// let another phone of the holder register a passkey on it.
// domain ‖ 0 ‖ user_id ‖ 0 ‖ challenge
func IdentityEnrolMessage(userID string, challenge []byte) []byte {
	return joinMessage(identityEnrolDomain, userID, challenge)
}

// IdentityRevokeMessage is the byte string an identity's recovery key signs to
// remove one phone from it and rotate the key.
// domain ‖ 0 ‖ user_id ‖ 0 ‖ challenge ‖ 0 ‖ device_tag ‖ 0 ‖ new_public_key (base64url, may be empty)
func IdentityRevokeMessage(userID string, challenge []byte, deviceTag, newPublicKey string) []byte {
	msg := joinMessage(identityRevokeDomain, userID, challenge)
	msg = append(msg, 0)
	msg = append(msg, deviceTag...)
	msg = append(msg, 0)
	return append(msg, newPublicKey...)
}

func joinMessage(domain, userID string, challenge []byte) []byte {
	msg := make([]byte, 0, len(domain)+len(userID)+len(challenge)+2)
	msg = append(msg, domain...)
	msg = append(msg, 0)
	msg = append(msg, userID...)
	msg = append(msg, 0)
	return append(msg, challenge...)
}

// --- in-memory stores ---

type enrolTicket struct {
	userID    string
	expiresAt time.Time
}

type pairingSlot struct {
	receiverKey string // the new phone's X25519 key, base64url
	senderKey   string
	blob        string
	expiresAt   time.Time
}

type deviceState struct {
	mu         sync.Mutex
	tickets    map[string]enrolTicket
	pairings   map[string]*pairingSlot
	relay      map[string][]relayItem
	relayBytes int
}

func newDeviceState() *deviceState {
	return &deviceState{tickets: map[string]enrolTicket{}, pairings: map[string]*pairingSlot{}, relay: map[string][]relayItem{}}
}

func (s *deviceState) sweep(now time.Time) {
	for k, v := range s.tickets {
		if now.After(v.expiresAt) {
			delete(s.tickets, k)
		}
	}
	for k, v := range s.pairings {
		if now.After(v.expiresAt) {
			delete(s.pairings, k)
		}
	}
	for k, q := range s.relay {
		keep := q[:0]
		for _, it := range q {
			if now.After(it.expiresAt) {
				s.relayBytes -= len(it.blob)
			} else {
				keep = append(keep, it)
			}
		}
		if len(keep) == 0 {
			delete(s.relay, k)
		} else {
			s.relay[k] = keep
		}
	}
}

func randomID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// SetWalletSessionEnder wires the fido2 hook that ends the wallet sessions of
// revoked passkeys.
func (h *Handler) SetWalletSessionEnder(f func([]string)) { h.endSessions = f }

// SetSessionCredential wires the fido2 lookup of the passkey behind a wallet
// session, so a phone revoking another never removes its own passkey.
func (h *Handler) SetSessionCredential(f func(string) string) { h.sessionCredential = f }

func (h *Handler) callerCredential(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if h.sessionCredential == nil || !strings.HasPrefix(auth, "Bearer wallet:") {
		return ""
	}
	return h.sessionCredential(strings.TrimPrefix(auth, "Bearer wallet:"))
}

// --- enrolment ---

// HandleEnrolTicket mints a one-time ticket that lets another phone of the
// caller register a passkey on the caller's account.
// POST /devices/enrol-ticket  (requires the account's wallet session or bearer)
// → {"ticket": "...", "expires_in": 600}
func (h *Handler) HandleEnrolTicket(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	t := randomID()
	h.devices.mu.Lock()
	h.devices.sweep(time.Now())
	h.devices.tickets[t] = enrolTicket{userID: userID, expiresAt: time.Now().Add(enrolTicketTTL)}
	h.devices.mu.Unlock()
	writeJSONStatus(w, http.StatusOK, map[string]any{"ticket": t, "expires_in": int(enrolTicketTTL.Seconds())})
}

// HandleRedeemEnrolTicket opens the account to one more passkey for an hour.
// POST /devices/enrol  {"ticket": "..."}  → {"user_id": "..."}
func (h *Handler) HandleRedeemEnrolTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Ticket == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "ticket is required"})
		return
	}
	if !h.allow(w, r, "enrol-ip", clientIP(r), enrolsPerIP) {
		return
	}
	h.devices.mu.Lock()
	t, ok := h.devices.tickets[req.Ticket]
	delete(h.devices.tickets, req.Ticket)
	h.devices.mu.Unlock()
	if !ok || time.Now().After(t.expiresAt) {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "ticket expired or already used"})
		return
	}
	if err := h.db.GrantEnrolment(GenerateID(), t.userID); err != nil {
		log.Printf("[devices] grant enrolment: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]string{"user_id": t.userID})
}

// verifyIdentitySignature pops the challenge and checks a signature by the
// identity's current recovery key over msg(challenge). Writes the error
// response and returns false when anything does not hold.
func (h *Handler) verifyIdentitySignature(w http.ResponseWriter, userID, challengeB64, signatureB64 string, msg func([]byte) []byte) bool {
	challenge, err1 := decodeB64URL(challengeB64)
	sig, err2 := decodeB64URL(signatureB64)
	if userID == "" || err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "user_id, challenge and signature are required"})
		return false
	}
	owner, ok := h.identityChallenges.pop(challenge)
	if !ok || owner != userID {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "challenge expired or not issued for this identity"})
		return false
	}
	pub, err := h.db.GetIdentityRecoveryKey(userID)
	if err != nil || pub == nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "this identity has no recovery key"})
		return false
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg(challenge), sig) {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "signature does not match this identity's recovery key"})
		return false
	}
	return true
}

// HandleEnrolIdentity lets another phone of the holder register a passkey on
// one identity, keeping the passkeys already there.
// POST /recovery/identity/enrol  {"user_id", "challenge", "signature"}
// (challenge from /recovery/identity/begin)
func (h *Handler) HandleEnrolIdentity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    string `json:"user_id"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if !h.verifyIdentitySignature(w, req.UserID, req.Challenge, req.Signature, func(c []byte) []byte {
		return IdentityEnrolMessage(req.UserID, c)
	}) {
		return
	}
	if err := h.db.GrantEnrolment(GenerateID(), req.UserID); err != nil {
		log.Printf("[devices] identity enrolment: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]string{"status": "enrolled", "user_id": req.UserID})
}

// --- revocation ---

func (h *Handler) revoke(userID, deviceTag, keep string) ([]string, error) {
	ids, err := h.db.RevokeDevice(userID, deviceTag, keep)
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 && h.endSessions != nil {
		h.endSessions(ids)
	}
	log.Printf("[devices] revoked %d passkey(s) of one phone on %s…", len(ids), userID[:min(8, len(userID))])
	return ids, nil
}

// HandleRevokePhone removes one phone from the caller's account: its passkeys,
// its push target, its open wallet sessions and anything waiting for it.
// POST /devices/revoke  {"device_tag": "...", "keep_credential_id": "..."}
// (requires a wallet session or bearer on that account; a wallet session's own
// passkey is always kept)
func (h *Handler) HandleRevokePhone(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	var req struct {
		DeviceTag        string `json:"device_tag"`
		KeepCredentialID string `json:"keep_credential_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || !store.ValidDeviceTag(req.DeviceTag) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "device_tag is required"})
		return
	}
	keep := h.callerCredential(r)
	if keep == "" {
		keep = req.KeepCredentialID
	}
	ids, err := h.revoke(userID, req.DeviceTag, keep)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	h.devices.mu.Lock()
	h.devices.dropRelay(relayKey(userID, req.DeviceTag))
	h.devices.mu.Unlock()
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "revoked", "passkeys": len(ids)})
}

// HandleRevokeIdentityDevice removes one phone from one identity and rotates
// the identity's recovery key, by a signature of the current key.
// POST /recovery/identity/revoke-device
// {"user_id", "device_tag", "keep_credential_id", "new_public_key", "challenge", "signature"}
func (h *Handler) HandleRevokeIdentityDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID           string `json:"user_id"`
		DeviceTag        string `json:"device_tag"`
		KeepCredentialID string `json:"keep_credential_id"`
		NewPublicKey     string `json:"new_public_key"`
		Challenge        string `json:"challenge"`
		Signature        string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || !store.ValidDeviceTag(req.DeviceTag) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "user_id, device_tag, challenge and signature are required"})
		return
	}
	var newPub []byte
	if req.NewPublicKey != "" {
		var err error
		newPub, err = decodeB64URL(req.NewPublicKey)
		if err != nil || len(newPub) != ed25519.PublicKeySize {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "new_public_key must be a base64url Ed25519 public key"})
			return
		}
	}
	if !h.verifyIdentitySignature(w, req.UserID, req.Challenge, req.Signature, func(c []byte) []byte {
		return IdentityRevokeMessage(req.UserID, c, req.DeviceTag, req.NewPublicKey)
	}) {
		return
	}
	ids, err := h.revoke(req.UserID, req.DeviceTag, req.KeepCredentialID)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if newPub != nil {
		if err := h.db.ReplaceIdentityRecoveryKey(req.UserID, newPub); err != nil {
			log.Printf("[devices] rotate recovery key: %v", err)
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "revoked", "passkeys": len(ids), "rotated": newPub != nil})
}

// --- pairing ---

// HandleOpenPairing opens a slot for a new phone.
// POST /devices/pair  {"public_key": "<base64url X25519>"}  → {"slot": "...", "expires_in": 600}
func (h *Handler) HandleOpenPairing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if k, err := decodeB64URL(req.PublicKey); err != nil || len(k) != 32 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "public_key must be a base64url X25519 key"})
		return
	}
	if !h.allow(w, r, "pair-ip", clientIP(r), pairingsPerIP) {
		return
	}
	slot := randomID()
	h.devices.mu.Lock()
	h.devices.sweep(time.Now())
	h.devices.pairings[slot] = &pairingSlot{receiverKey: req.PublicKey, expiresAt: time.Now().Add(pairingTTL)}
	h.devices.mu.Unlock()
	writeJSONStatus(w, http.StatusOK, map[string]any{"slot": slot, "expires_in": int(pairingTTL.Seconds())})
}

// HandleFillPairing puts the sealed transfer into a slot, once.
// PUT /devices/pair/{slot}  {"sender_public_key": "...", "blob": "..."}
// (requires a wallet session or bearer: only a signed-in phone sends)
func (h *Handler) HandleFillPairing(w http.ResponseWriter, r *http.Request) {
	if h.authenticateBearer(w, r) == "" {
		return
	}
	var req struct {
		SenderPublicKey string `json:"sender_public_key"`
		Blob            string `json:"blob"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPairingBlob+4096)).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if k, err := decodeB64URL(req.SenderPublicKey); err != nil || len(k) != 32 || req.Blob == "" || len(req.Blob) > maxPairingBlob || !backupBlobShape.MatchString(req.Blob) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "sender_public_key and a base64url blob are required"})
		return
	}
	h.devices.mu.Lock()
	defer h.devices.mu.Unlock()
	s, ok := h.devices.pairings[r.PathValue("slot")]
	if !ok || time.Now().After(s.expiresAt) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "pairing expired"})
		return
	}
	if s.blob != "" {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "pairing already used"})
		return
	}
	s.senderKey, s.blob = req.SenderPublicKey, req.Blob
	writeJSONStatus(w, http.StatusOK, map[string]string{"status": "sent"})
}

// HandleReadPairing gives the new phone the transfer and closes the slot.
// GET /devices/pair/{slot}  → 200 {"sender_public_key", "blob"} | 202 (waiting) | 404
func (h *Handler) HandleReadPairing(w http.ResponseWriter, r *http.Request) {
	slot := r.PathValue("slot")
	h.devices.mu.Lock()
	defer h.devices.mu.Unlock()
	s, ok := h.devices.pairings[slot]
	if !ok || time.Now().After(s.expiresAt) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "pairing expired"})
		return
	}
	if s.blob == "" {
		writeJSONStatus(w, http.StatusAccepted, map[string]string{"status": "waiting"})
		return
	}
	delete(h.devices.pairings, slot)
	writeJSONStatus(w, http.StatusOK, map[string]string{"sender_public_key": s.senderKey, "blob": s.blob})
}

// --- relay between phones ---
//
// Phones of one holder pass sealed updates (a profile change, a request for a
// full sync) through here. Nothing is stored: an update waits in memory for at
// most relayTTL, and a silent push wakes the phone it is for. Reading takes it.
// The sending wallet keeps its own outbox and sends again until the other phone
// confirms, through this same relay, that it has the update.

type relayItem struct {
	blob      string
	expiresAt time.Time
}

func relayKey(userID, tag string) string { return userID + "/" + tag }

// dropRelay forgets what waits for one phone (it was revoked). Locked by caller.
func (s *deviceState) dropRelay(key string) {
	for _, it := range s.relay[key] {
		s.relayBytes -= len(it.blob)
	}
	delete(s.relay, key)
}

// HandlePostRelay passes sealed updates to other phones of the caller.
// POST /devices/relay  {"items": [{"to": "<device tag>", "blob": "..."}]}
func (h *Handler) HandlePostRelay(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	var req struct {
		Items []struct {
			To   string `json:"to"`
			Blob string `json:"blob"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxDevices*maxRelayBlob+4096)).Decode(&req); err != nil || len(req.Items) == 0 || len(req.Items) > maxDevices {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "1 to 5 items are required"})
		return
	}
	for _, it := range req.Items {
		if !store.ValidDeviceTag(it.To) || it.Blob == "" || len(it.Blob) > maxRelayBlob || !backupBlobShape.MatchString(it.Blob) {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "each item needs a device tag and a base64url blob of at most 1MiB"})
			return
		}
	}
	now := time.Now()
	h.devices.mu.Lock()
	h.devices.sweep(now)
	for _, it := range req.Items {
		if h.devices.relayBytes+len(it.Blob) > maxRelayTotal {
			h.devices.mu.Unlock()
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{"error": "relay busy, try again later"})
			return
		}
		key := relayKey(userID, it.To)
		q := h.devices.relay[key]
		if len(q) >= maxRelayPerPhone {
			// The sender resends whatever the other phone never confirms.
			h.devices.relayBytes -= len(q[0].blob)
			q = q[1:]
		}
		h.devices.relay[key] = append(q, relayItem{blob: it.Blob, expiresAt: now.Add(relayTTL)})
		h.devices.relayBytes += len(it.Blob)
	}
	h.devices.mu.Unlock()
	for _, it := range req.Items {
		go h.wake(userID, it.To)
	}
	writeJSONStatus(w, http.StatusOK, map[string]string{"status": "relayed"})
}

// wake sends a silent push to one phone of the account, telling it to read the
// relay. Best effort: the phone reads it anyway when next opened.
func (h *Handler) wake(userID, tag string) {
	for _, t := range h.db.GetDevicePushTargets(userID, tag) {
		if err := push.Notify(context.Background(), h.db, userID, push.Message{
			Token: t.Token, Background: true, Data: map[string]string{"type": "device-relay"},
		}); err != nil {
			log.Printf("[devices] wake: %v", err)
		}
	}
}

// HandleGetRelay hands one phone of the caller what waits for it, and forgets it.
// GET /devices/relay?tag=<device tag>  → {"items": ["<blob>", ...]}
func (h *Handler) HandleGetRelay(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	tag := r.URL.Query().Get("tag")
	if !store.ValidDeviceTag(tag) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "tag is required"})
		return
	}
	key := relayKey(userID, tag)
	now := time.Now()
	h.devices.mu.Lock()
	q := h.devices.relay[key]
	h.devices.dropRelay(key)
	h.devices.mu.Unlock()
	out := make([]string, 0, len(q))
	for _, it := range q {
		if now.Before(it.expiresAt) {
			out = append(out, it.blob)
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"items": out})
}
