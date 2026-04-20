// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// WalletSessionResolver resolves a short-lived wallet sessionToken to a user_id.
// Implemented by the fido2 package; injected to avoid an import cycle.
type WalletSessionResolver func(token string) (string, bool)

// Handler serves all recovery-related HTTP endpoints.
type Handler struct {
	db            *store.DB
	mailer        *Mailer
	issuer        *tokens.Issuer
	walletSession WalletSessionResolver
}

// NewHandler creates a recovery handler.
func NewHandler(db *store.DB, mailer *Mailer, issuer *tokens.Issuer) *Handler {
	return &Handler{db: db, mailer: mailer, issuer: issuer}
}

// SetWalletSessionResolver wires the fido2 wallet-session lookup into recovery auth.
func (h *Handler) SetWalletSessionResolver(r WalletSessionResolver) {
	h.walletSession = r
}

// --- Recovery phrase endpoints ---

// HandleRegeneratePhrase creates a new BIP39 recovery phrase, replacing any existing one.
// POST /recovery/phrase/regenerate  (requires wallet sessionToken or JWT bearer)
func (h *Handler) HandleRegeneratePhrase(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	phrase, err := GenerateRecoveryPhrase()
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if err := h.db.StoreRecoveryCodes(userID, []string{HashPhrase(phrase)}); err != nil {
		log.Printf("[recovery] store phrase error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"phrase":  phrase,
		"message": "Save this 24-word phrase securely. It will not be shown again.",
	})
}

// HandlePhraseStatus returns whether the user has a recovery phrase set up.
// GET /recovery/phrase/status?user_id=...  (public — only exposes a boolean)
func (h *Handler) HandlePhraseStatus(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		// Fall back to bearer auth for backward compatibility.
		userID = h.authenticateBearer(w, r)
		if userID == "" {
			return
		}
	}

	count, err := h.db.HasRecoveryCodes(userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"has_phrase": count > 0,
		// Legacy field for old wallet builds — count is always 0 or 1 now.
		"has_codes":       count > 0,
		"remaining_codes": count,
	})
}

// HandleDeleteRecoveryCodes deactivates recovery codes (requires ≥1 accepted guardian).
// DELETE /recovery/codes  (requires Bearer token)
func (h *Handler) HandleDeleteRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	// Must have at least one accepted guardian to deactivate codes.
	accepted, _, err := h.db.GetAcceptedGuardianCount(userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if accepted < 1 {
		http.Error(w, `{"error":"you must have at least one accepted guardian before deactivating recovery codes"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.DeleteRecoveryCodes(userID); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"deleted"}`))
}

// --- Recovery flow endpoints ---

// HandleBeginRecovery starts the recovery process using a BIP39 recovery phrase.
// No device attestation or rate limiting — protection comes from 256-bit phrase entropy.
// POST /recovery/begin  { "recovery_phrase": "word1 word2 ..." }
// (Legacy field "recovery_code" still accepted for backward compatibility.)
func (h *Handler) HandleBeginRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RecoveryPhrase string `json:"recovery_phrase"`
		RecoveryCode   string `json:"recovery_code"` // legacy alias
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	phrase := req.RecoveryPhrase
	if phrase == "" {
		phrase = req.RecoveryCode
	}
	if phrase == "" {
		http.Error(w, `{"error":"recovery_phrase is required"}`, http.StatusBadRequest)
		return
	}

	// --- Find user by recovery phrase ---
	codeHash := HashPhrase(phrase)
	userID, err := h.db.FindUserByRecoveryCode(codeHash)
	if err != nil {
		http.Error(w, `{"error":"invalid recovery phrase"}`, http.StatusBadRequest)
		return
	}

	// Check if guardians are required.
	acceptedGuardians, threshold, err := h.db.GetAcceptedGuardianCount(userID)
	if err != nil {
		log.Printf("[recovery] guardian check error: %v", err)
	}

	guardiansRequired := 0
	if acceptedGuardians > 0 && threshold > 0 {
		guardiansRequired = threshold
	}

	// Create recovery request.
	requestID := GenerateID()
	expiresAt := time.Now().Add(1 * time.Hour)
	if err := h.db.CreateRecoveryRequest(requestID, userID, guardiansRequired, expiresAt); err != nil {
		log.Printf("[recovery] create request error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Mark phrase as verified on the request.
	h.db.UpdateRecoveryCodeVerified(requestID)

	// If guardians required, notify them.
	if guardiansRequired > 0 {
		go h.notifyGuardians(userID)
	}

	status := "approved"
	if guardiansRequired > 0 {
		status = "awaiting_guardians"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"request_id":         requestID,
		"user_id":            userID,
		"status":             status,
		"guardians_required": guardiansRequired,
		"guardians_approved": 0,
		"expires_at":         expiresAt.UTC().Format(time.RFC3339),
	})
}

// HandleRecoveryStatus checks the status of a recovery request.
// GET /recovery/status?request_id=...
func (h *Handler) HandleRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		http.Error(w, `{"error":"request_id is required"}`, http.StatusBadRequest)
		return
	}

	req, err := h.db.GetRecoveryRequest(requestID)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	status := req.Status
	if req.GuardiansRequired > 0 && req.GuardiansApproved >= req.GuardiansRequired {
		status = "approved"
	} else if req.GuardiansRequired > 0 {
		status = "awaiting_guardians"
	} else {
		status = "approved"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"request_id":         requestID,
		"status":             status,
		"guardians_required": req.GuardiansRequired,
		"guardians_approved": req.GuardiansApproved,
		"expires_at":         req.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// HandleCompleteRecovery completes recovery — revokes old credentials, allows FIDO2 re-registration.
// POST /recovery/complete  { "request_id": "..." }
func (h *Handler) HandleCompleteRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RequestID == "" {
		http.Error(w, `{"error":"request_id is required"}`, http.StatusBadRequest)
		return
	}

	rr, err := h.db.GetRecoveryRequest(req.RequestID)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	// Check all factors are satisfied.
	if !rr.CodeVerified {
		http.Error(w, `{"error":"recovery code must be verified"}`, http.StatusBadRequest)
		return
	}
	if rr.GuardiansRequired > 0 && rr.GuardiansApproved < rr.GuardiansRequired {
		http.Error(w, `{"error":"insufficient guardian approvals"}`, http.StatusBadRequest)
		return
	}

	// Execute recovery: revoke old credentials + codes + refresh tokens.
	if err := h.db.CompleteRecovery(req.RequestID, rr.UserID); err != nil {
		log.Printf("[recovery] complete error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "completed",
		"user_id": rr.UserID,
		"message": "Account recovered. Register a new FIDO2 credential via /fido2/register/begin with user_id.",
	})
}

// --- Guardian endpoints ---

// HandleListGuardians returns the user's guardians.
// GET /guardians  (requires Bearer token)
func (h *Handler) HandleListGuardians(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	guardians, threshold, err := h.db.ListGuardians(userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"guardians": guardians,
		"threshold": threshold,
	})
}

// HandleInviteGuardianByEmail sends an email invitation with a deep link.
// POST /guardians/invite  { "guardian_email": "friend@example.com", "threshold": 2, "user_name": "Alice" }
func (h *Handler) HandleInviteGuardianByEmail(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	var req struct {
		GuardianEmail string `json:"guardian_email"`
		Threshold     int    `json:"threshold"`
		UserName      string `json:"user_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.GuardianEmail == "" {
		http.Error(w, `{"error":"guardian_email is required"}`, http.StatusBadRequest)
		return
	}
	if req.Threshold < 1 {
		req.Threshold = 1
	}

	// Rate limit: max 10 invitations per user per day.
	count, err := h.db.GuardianInviteRateCheck(userID)
	if err != nil {
		log.Printf("[recovery] invite rate check error: %v", err)
	}
	if count >= 10 {
		http.Error(w, `{"error":"too many invitations today, try again tomorrow"}`, http.StatusTooManyRequests)
		return
	}

	// Create invitation with token.
	inviteToken := GenerateID()
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days

	if err := h.db.CreateGuardianInvite(inviteToken, userID, expiresAt); err != nil {
		log.Printf("[recovery] create invite error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Send email with deep link.
	go func() {
		if err := h.mailer.SendGuardianInvite(req.GuardianEmail, req.UserName, inviteToken); err != nil {
			log.Printf("[recovery] failed to send guardian invite email: %v", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":       "invited",
		"invite_token": inviteToken,
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"message":      "guardian invitation email sent",
	})
}

// HandleAddGuardianByQR adds a guardian directly by user_id (from QR code scan).
// POST /guardians/add  { "guardian_id": "...", "threshold": 2 }
func (h *Handler) HandleAddGuardianByQR(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	var req struct {
		GuardianID string `json:"guardian_id"`
		Threshold  int    `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.GuardianID == "" {
		http.Error(w, `{"error":"guardian_id is required"}`, http.StatusBadRequest)
		return
	}
	if req.Threshold < 1 {
		req.Threshold = 1
	}

	// Cannot be your own guardian.
	if req.GuardianID == userID {
		http.Error(w, `{"error":"you cannot be your own guardian"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.AddGuardian(userID, req.GuardianID, req.Threshold); err != nil {
		log.Printf("[recovery] add guardian error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "pending",
		"message": "guardian added, awaiting confirmation",
	})
}

// HandleAcceptGuardianInviteByToken accepts an email-based invitation using the invite token.
// POST /guardians/accept-invite  { "invite_token": "..." }  (requires Bearer token — guardian's token)
func (h *Handler) HandleAcceptGuardianInviteByToken(w http.ResponseWriter, r *http.Request) {
	guardianID := h.authenticateBearer(w, r)
	if guardianID == "" {
		return
	}

	var req struct {
		InviteToken string `json:"invite_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.InviteToken == "" {
		http.Error(w, `{"error":"invite_token is required"}`, http.StatusBadRequest)
		return
	}

	// Look up the invitation.
	inv, err := h.db.GetGuardianInvite(req.InviteToken)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	// Cannot be your own guardian.
	if inv.UserID == guardianID {
		http.Error(w, `{"error":"you cannot be your own guardian"}`, http.StatusBadRequest)
		return
	}

	// Accept the invitation.
	if err := h.db.AcceptGuardianInvite(req.InviteToken, guardianID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	// Also create the guardian relationship.
	threshold := 1 // Default; user can adjust threshold later.
	if err := h.db.AddGuardian(inv.UserID, guardianID, threshold); err != nil {
		log.Printf("[recovery] add guardian from invite error: %v", err)
	}
	// Auto-accept since the guardian explicitly accepted via invite link.
	h.db.RespondToGuardianInvite(inv.UserID, guardianID, true)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"user_id": inv.UserID,
	})
}

// HandleRemoveGuardian removes a guardian.
// DELETE /guardians?guardian_id=...  (requires Bearer token)
func (h *Handler) HandleRemoveGuardian(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	guardianID := r.URL.Query().Get("guardian_id")
	if guardianID == "" {
		http.Error(w, `{"error":"guardian_id is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.RemoveGuardian(userID, guardianID); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"removed"}`))
}

// HandleRespondToGuardianInvite lets a guardian accept or decline a direct (QR-based) invitation.
// POST /guardians/respond  { "user_id": "...", "accept": true }  (requires Bearer token — guardian's token)
func (h *Handler) HandleRespondToGuardianInvite(w http.ResponseWriter, r *http.Request) {
	guardianID := h.authenticateBearer(w, r)
	if guardianID == "" {
		return
	}

	var req struct {
		UserID string `json:"user_id"`
		Accept bool   `json:"accept"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, `{"error":"user_id is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.RespondToGuardianInvite(req.UserID, guardianID, req.Accept); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	status := "declined"
	if req.Accept {
		status = "accepted"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

// HandleApproveRecovery lets a guardian approve a recovery request.
// POST /guardians/approve  { "request_id": "..." }  (requires Bearer token — guardian's token)
func (h *Handler) HandleApproveRecovery(w http.ResponseWriter, r *http.Request) {
	guardianID := h.authenticateBearer(w, r)
	if guardianID == "" {
		return
	}

	var req struct {
		RequestID string `json:"request_id"`
		Approved  bool   `json:"approved"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RequestID == "" {
		http.Error(w, `{"error":"request_id is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.ApproveRecovery(req.RequestID, guardianID, req.Approved); err != nil {
		log.Printf("[recovery] approve error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
}

// HandleListPendingGuardianInvites returns invitations addressed to the authenticated user.
// GET /guardians/invites  (requires Bearer token)
func (h *Handler) HandleListPendingGuardianInvites(w http.ResponseWriter, r *http.Request) {
	guardianID := h.authenticateBearer(w, r)
	if guardianID == "" {
		return
	}

	invites, err := h.db.ListPendingGuardianInvites(guardianID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"invites": invites})
}

// HandleListRecoveryRequests returns active recovery requests for the authenticated guardian.
// GET /guardians/recovery-requests  (requires Bearer token)
func (h *Handler) HandleListRecoveryRequests(w http.ResponseWriter, r *http.Request) {
	guardianID := h.authenticateBearer(w, r)
	if guardianID == "" {
		return
	}

	requests, err := h.db.ListActiveRecoveryRequests(guardianID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"requests": requests})
}

// HandleGetGuardianQR returns the user's QR code data for guardian identification.
// GET /guardians/qr  (requires Bearer token)
func (h *Handler) HandleGetGuardianQR(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"user_id": userID,
	})
}

// --- Device management endpoints ---

// HandleListDevices returns credentials/devices for the authenticated user.
// GET /devices  (requires Bearer token)
func (h *Handler) HandleListDevices(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	devices, err := h.db.ListCredentials(userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"devices": devices})
}

// HandleRevokeDevice removes a specific credential.
// DELETE /devices?credential_id=...  (requires Bearer token)
func (h *Handler) HandleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	credID := r.URL.Query().Get("credential_id")
	if credID == "" {
		http.Error(w, `{"error":"credential_id is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.RevokeCredential(userID, credID); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"revoked"}`))
}

// HandleRegisterPushToken stores the wallet's Expo push token for this user.
// POST /push-token  { "push_token": "ExponentPushToken[...]" }
func (h *Handler) HandleRegisterPushToken(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	var req struct {
		PushToken string `json:"push_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PushToken == "" {
		http.Error(w, `{"error":"push_token is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.UpsertPushToken(userID, req.PushToken); err != nil {
		log.Printf("[push-token] upsert failed for %s: %v", userID, err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// --- Helpers ---

// authenticateBearer extracts and validates the Bearer token, returning the user ID.
// Accepts two forms:
//   - "Bearer <jwt>"           — OIDC access token (verified via tokens.Issuer)
//   - "Bearer wallet:<token>"  — short-lived wallet session token issued by /fido2/*/complete
func (h *Handler) authenticateBearer(w http.ResponseWriter, r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
		return ""
	}
	token := auth[7:]

	// Wallet session token path.
	if strings.HasPrefix(token, "wallet:") && h.walletSession != nil {
		walletToken := strings.TrimPrefix(token, "wallet:")
		if userID, ok := h.walletSession(walletToken); ok {
			return userID
		}
		http.Error(w, `{"error":"invalid or expired wallet session"}`, http.StatusUnauthorized)
		return ""
	}

	// OIDC JWT path.
	claims, err := h.issuer.VerifyAccessToken(token)
	if err != nil {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return ""
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		http.Error(w, `{"error":"invalid token claims"}`, http.StatusUnauthorized)
		return ""
	}
	return sub
}

// notifyGuardians sends push notifications to all accepted guardians for a user.
func (h *Handler) notifyGuardians(userID string) {
	guardians, _, err := h.db.ListGuardians(userID)
	if err != nil {
		log.Printf("[recovery] list guardians error: %v", err)
		return
	}

	for _, g := range guardians {
		if g.Status != "accepted" {
			continue
		}
		pushToken := h.db.GetPushToken(g.GuardianID)
		if pushToken == "" {
			log.Printf("[recovery] guardian %s has no push token — skipping notification", g.GuardianID)
			continue
		}
		go h.sendGuardianPush(g.GuardianID, pushToken, userID)
	}
}

// sendGuardianPush sends a push notification to a guardian via Expo push service.
func (h *Handler) sendGuardianPush(guardianID, pushToken, recoveringUserID string) {
	payload, _ := json.Marshal([]map[string]interface{}{
		{
			"to":    pushToken,
			"sound": "default",
			"title": "Recovery request",
			"body":  "Someone you protect needs your help to recover their account.",
			"data": map[string]string{
				"type":    "recovery-request",
				"user_id": recoveringUserID,
			},
		},
	})

	req, err := http.NewRequest("POST", "https://exp.host/--/api/v2/push/send", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[recovery] push to guardian %s failed: %v", guardianID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[recovery] push to guardian %s failed: %v", guardianID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Printf("[recovery] push to guardian %s returned %d: %s", guardianID, resp.StatusCode, body)
		return
	}
	log.Printf("[recovery] push notification sent to guardian %s", guardianID)
}
