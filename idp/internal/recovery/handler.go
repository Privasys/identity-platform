// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// Handler serves all recovery-related HTTP endpoints.
type Handler struct {
	db     *store.DB
	mailer *Mailer
	issuer *tokens.Issuer
}

// NewHandler creates a recovery handler.
func NewHandler(db *store.DB, mailer *Mailer, issuer *tokens.Issuer) *Handler {
	return &Handler{db: db, mailer: mailer, issuer: issuer}
}

// --- Email verification endpoints ---

// HandleSendEmailCode sends a 6-digit OTP to the provided email.
// POST /recovery/email/send  { "email": "user@example.com" }
func (h *Handler) HandleSendEmailCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, `{"error":"email is required"}`, http.StatusBadRequest)
		return
	}

	// Rate limit: max 3 per email per hour.
	count, err := h.db.EmailVerificationRateCheck(req.Email)
	if err != nil {
		log.Printf("[recovery] rate check error: %v", err)
	}
	if count >= 3 {
		http.Error(w, `{"error":"too many verification attempts, try again later"}`, http.StatusTooManyRequests)
		return
	}

	code, err := GenerateOTP()
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	id := GenerateID()
	codeHash := HashCode(code)
	expiresAt := time.Now().Add(10 * time.Minute)

	if err := h.db.StoreEmailVerification(id, req.Email, codeHash, expiresAt); err != nil {
		log.Printf("[recovery] store verification error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Send email (async — don't block the response on Graph API).
	go func() {
		if err := h.mailer.SendVerificationCode(req.Email, code); err != nil {
			log.Printf("[recovery] failed to send verification email to %s: %v", req.Email, err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"verification_id": id,
		"message":         "verification code sent",
	})
}

// HandleVerifyEmailCode verifies the OTP and returns a verification token.
// POST /recovery/email/verify  { "email": "user@example.com", "code": "123456" }
func (h *Handler) HandleVerifyEmailCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Code == "" {
		http.Error(w, `{"error":"email and code are required"}`, http.StatusBadRequest)
		return
	}

	codeHash := HashCode(req.Code)
	verificationID, err := h.db.VerifyEmailCode(req.Email, codeHash)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"verification_id": verificationID,
		"email":           req.Email,
		"verified":        "true",
	})
}

// --- Recovery code endpoints ---

// HandleGenerateRecoveryCodes creates new recovery codes for an authenticated user.
// POST /recovery/codes  (requires Bearer token)
func (h *Handler) HandleGenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	codes, err := GenerateRecoveryCodes()
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	hashes := make([]string, len(codes))
	for i, code := range codes {
		hashes[i] = HashCode(code)
	}

	if err := h.db.StoreRecoveryCodes(userID, hashes); err != nil {
		log.Printf("[recovery] store codes error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"codes":   codes,
		"message": "Save these codes securely. They will not be shown again.",
	})
}

// HandleCheckRecoveryCodes returns whether the user has active recovery codes.
// GET /recovery/codes  (requires Bearer token)
func (h *Handler) HandleCheckRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	count, err := h.db.HasRecoveryCodes(userID)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"has_codes":       count > 0,
		"remaining_codes": count,
	})
}

// --- Recovery flow endpoints ---

// HandleBeginRecovery starts the recovery process.
// POST /recovery/begin  { "email": "user@example.com", "verification_id": "...", "recovery_code": "XXXX-XXXX-XXXX-XXXX" }
func (h *Handler) HandleBeginRecovery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email          string `json:"email"`
		VerificationID string `json:"verification_id"`
		RecoveryCode   string `json:"recovery_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.VerificationID == "" || req.RecoveryCode == "" {
		http.Error(w, `{"error":"email, verification_id, and recovery_code are required"}`, http.StatusBadRequest)
		return
	}

	// Step 1: Verify email verification token is valid.
	verifiedEmail, ok := h.db.IsEmailVerified(req.VerificationID)
	if !ok || verifiedEmail != req.Email {
		http.Error(w, `{"error":"email verification is invalid or expired"}`, http.StatusBadRequest)
		return
	}

	// Step 2: Find user by email.
	userID, err := h.db.FindUserByEmail(req.Email)
	if err != nil {
		http.Error(w, `{"error":"no account found with this email"}`, http.StatusNotFound)
		return
	}

	// Step 3: Verify recovery code.
	codeHash := HashCode(req.RecoveryCode)
	valid, err := h.db.VerifyRecoveryCode(userID, codeHash)
	if err != nil || !valid {
		http.Error(w, `{"error":"invalid recovery code"}`, http.StatusBadRequest)
		return
	}

	// Step 4: Check if guardians are required.
	acceptedGuardians, threshold, err := h.db.GetAcceptedGuardianCount(userID)
	if err != nil {
		log.Printf("[recovery] guardian check error: %v", err)
	}

	guardiansRequired := 0
	if acceptedGuardians > 0 && threshold > 0 {
		guardiansRequired = threshold
	}

	// Step 5: Create recovery request.
	requestID := GenerateID()
	expiresAt := time.Now().Add(1 * time.Hour)
	if err := h.db.CreateRecoveryRequest(requestID, userID, guardiansRequired, expiresAt); err != nil {
		log.Printf("[recovery] create request error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Mark email + code as verified on the request.
	h.db.UpdateRecoveryRequest(requestID, true, true)

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
	if !rr.EmailVerified || !rr.CodeVerified {
		http.Error(w, `{"error":"email and recovery code must be verified"}`, http.StatusBadRequest)
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

// HandleInviteGuardian invites a guardian by email.
// POST /guardians  { "guardian_email": "friend@example.com", "threshold": 2 }
func (h *Handler) HandleInviteGuardian(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}

	var req struct {
		GuardianEmail string `json:"guardian_email"`
		Threshold     int    `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.GuardianEmail == "" {
		http.Error(w, `{"error":"guardian_email is required"}`, http.StatusBadRequest)
		return
	}
	if req.Threshold < 1 {
		req.Threshold = 1
	}

	// Find guardian by email — must be an existing Privasys ID user.
	guardianID, err := h.db.FindUserByEmail(req.GuardianEmail)
	if err != nil {
		http.Error(w, `{"error":"guardian must be an existing Privasys ID user with a verified email"}`, http.StatusNotFound)
		return
	}

	// Cannot be your own guardian.
	if guardianID == userID {
		http.Error(w, `{"error":"you cannot be your own guardian"}`, http.StatusBadRequest)
		return
	}

	if err := h.db.AddGuardian(userID, guardianID, req.GuardianEmail, req.Threshold); err != nil {
		log.Printf("[recovery] add guardian error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Notify guardian via email and push.
	go func() {
		// Get user's display name for the notification.
		users, _ := h.db.ListUsers()
		userName := "A Privasys user"
		for _, u := range users {
			if u.UserID == userID {
				userName = u.DisplayName
				if userName == "" {
					userName = u.Email
				}
				break
			}
		}
		if err := h.mailer.SendGuardianInvite(req.GuardianEmail, userName); err != nil {
			log.Printf("[recovery] failed to send guardian invite email: %v", err)
		}
		// TODO: also send push notification via broker.
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "invited",
		"message": "guardian invitation sent",
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

// HandleRespondToGuardianInvite lets a guardian accept or decline.
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

// --- Helpers ---

// authenticateBearer extracts and validates the Bearer token, returning the user ID.
func (h *Handler) authenticateBearer(w http.ResponseWriter, r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || auth[:7] != "Bearer " {
		http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
		return ""
	}
	token := auth[7:]

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

// notifyGuardians sends email + push to all accepted guardians for a user.
func (h *Handler) notifyGuardians(userID string) {
	guardians, _, err := h.db.ListGuardians(userID)
	if err != nil {
		log.Printf("[recovery] list guardians error: %v", err)
		return
	}

	// Get user name for notification.
	users, _ := h.db.ListUsers()
	userName := "A Privasys user"
	for _, u := range users {
		if u.UserID == userID {
			userName = u.DisplayName
			if userName == "" {
				userName = u.Email
			}
			break
		}
	}

	for _, g := range guardians {
		if g.Status == "accepted" {
			if err := h.mailer.SendRecoveryAlert(g.GuardianEmail, userName); err != nil {
				log.Printf("[recovery] failed to send recovery alert to %s: %v", g.GuardianEmail, err)
			}
			// TODO: also send push notification via broker.
		}
	}
}
