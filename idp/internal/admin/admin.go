// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package admin implements administrative endpoints for the IdP:
// role management and service account registration.
package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"

	"github.com/Privasys/idp/internal/store"
)

// HandleGetMetrics handles GET /admin/metrics — aggregate usage statistics (no PII).
func HandleGetMetrics(db *store.DB, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAdmin(w, r, adminToken) {
			return
		}

		metrics, err := db.GetMetrics()
		if err != nil {
			log.Printf("admin/metrics: failed: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to get metrics")
			return
		}

		writeJSON(w, http.StatusOK, metrics)
	}
}

// HandleGrantRole handles POST /admin/roles — assign a role to a user.
//
//	Request: {"user_id": "...", "role": "platform:admin"}
//	Response: {"status": "ok"}
func HandleGrantRole(db *store.DB, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAdmin(w, r, adminToken) {
			return
		}

		var req struct {
			UserID string `json:"user_id"`
			Role   string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.UserID == "" || req.Role == "" {
			writeError(w, http.StatusBadRequest, "user_id and role are required")
			return
		}

		if err := db.GrantRole(req.UserID, req.Role, "admin"); err != nil {
			log.Printf("admin/roles: grant failed: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to grant role")
			return
		}

		log.Printf("admin: granted role %q to user %s", req.Role, req.UserID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// HandleRevokeRole handles DELETE /admin/roles — revoke a role from a user.
//
//	Request: {"user_id": "...", "role": "platform:manager"}
//	Response: {"status": "ok"}
func HandleRevokeRole(db *store.DB, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAdmin(w, r, adminToken) {
			return
		}

		var req struct {
			UserID string `json:"user_id"`
			Role   string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.UserID == "" || req.Role == "" {
			writeError(w, http.StatusBadRequest, "user_id and role are required")
			return
		}

		if err := db.RevokeRole(req.UserID, req.Role); err != nil {
			log.Printf("admin/roles: revoke failed: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to revoke role")
			return
		}

		log.Printf("admin: revoked role %q from user %s", req.Role, req.UserID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// HandleListRoles handles GET /admin/roles?user_id=... — list roles for a user.
func HandleListRoles(db *store.DB, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAdmin(w, r, adminToken) {
			return
		}

		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			writeError(w, http.StatusBadRequest, "user_id query parameter required")
			return
		}

		roles, err := db.GetRoles(userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list roles")
			return
		}
		if roles == nil {
			roles = []string{}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"user_id": userID,
			"roles":   roles,
		})
	}
}

// HandleCreateServiceAccount handles POST /admin/service-accounts.
// Creates a service account with an RSA-2048 key pair and returns the private key.
//
//	Request: {"display_name": "management-service"}
//	Response: {"account_id": "...", "key_id": "...", "key": "-----BEGIN RSA PRIVATE KEY-----\n...",
//	           "type": "serviceaccount"}
func HandleCreateServiceAccount(db *store.DB, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAdmin(w, r, adminToken) {
			return
		}

		var req struct {
			DisplayName string `json:"display_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.DisplayName == "" {
			writeError(w, http.StatusBadRequest, "display_name is required")
			return
		}

		// Generate RSA-2048 key pair.
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "key generation failed")
			return
		}

		// Encode public key as PEM.
		pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "public key encoding failed")
			return
		}
		pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

		// Encode private key as PEM (PKCS#1 RSA private key format).
		privPEM := string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		}))

		// Generate account ID and key ID.
		idBytes := make([]byte, 16)
		rand.Read(idBytes)
		accountID := hex.EncodeToString(idBytes)

		kidBytes := make([]byte, 8)
		rand.Read(kidBytes)
		keyID := hex.EncodeToString(kidBytes)

		// Store in DB.
		if err := db.CreateServiceAccount(accountID, req.DisplayName, pubPEM, keyID); err != nil {
			log.Printf("admin/service-accounts: create failed: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to create service account")
			return
		}

		log.Printf("admin: created service account %s (%s)", accountID, req.DisplayName)

		// Return the key file in a format compatible with the management service's serviceKeyFile struct.
		writeJSON(w, http.StatusCreated, map[string]string{
			"type":      "serviceaccount",
			"keyId":     keyID,
			"key":       privPEM,
			"userId":    accountID,
			"accountId": accountID,
		})
	}
}

func checkAdmin(w http.ResponseWriter, r *http.Request, adminToken string) bool {
	if adminToken == "" {
		return true // no admin token configured — allow all (dev mode)
	}
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || auth[7:] != adminToken {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// BootstrapAdmin is the env var name for auto-granting platform:admin to a user on startup.
const BootstrapAdmin = "IDP_BOOTSTRAP_ADMIN"

// MaybeBootstrapAdmin grants platform:admin to the user specified by IDP_BOOTSTRAP_ADMIN env var.
func MaybeBootstrapAdmin(db *store.DB, sub string) {
	if sub == "" {
		return
	}
	if err := db.GrantRole(sub, "platform:admin", "bootstrap"); err != nil {
		log.Printf("bootstrap: failed to grant admin to %s: %v", sub, err)
		return
	}
	log.Printf("bootstrap: granted platform:admin to %s", sub)
}
