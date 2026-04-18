// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package e2e provides a test-only token endpoint for CI/e2e tests.
// It is conditionally registered only when IDP_E2E_SECRET is configured
// and MUST NEVER be enabled in production.
package e2e

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

const (
	e2eUserID      = "e2e:test-user"
	e2eDisplayName = "E2E Test User"
	e2eEmail       = "e2e@test.privasys.org"
)

// HandleToken returns a handler that issues tokens for an e2e test user
// without requiring FIDO2 or wallet authentication.
//
// Request:  POST /e2e/token
//
//	Header: X-E2E-Secret: <shared secret>
//	Body (optional JSON): {"client_id": "privasys-platform"}
//
// Response: {"access_token": "...", "id_token": "...", "token_type": "Bearer", "expires_in": 300}
func HandleToken(secret string, issuer *tokens.Issuer, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate secret.
		if r.Header.Get("X-E2E-Secret") != secret {
			http.Error(w, `{"error":"forbidden","error_description":"invalid e2e secret"}`, http.StatusForbidden)
			return
		}

		// Parse optional body.
		clientID := "privasys-platform"
		if r.Body != nil && r.ContentLength > 0 {
			var body struct {
				ClientID string `json:"client_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.ClientID != "" {
				clientID = body.ClientID
			}
		}

		// Ensure e2e user exists in DB.
		if err := ensureE2EUser(db); err != nil {
			log.Printf("e2e: failed to ensure test user: %v", err)
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}

		// Get roles.
		roles, _ := db.GetRoles(e2eUserID)

		// Issue access token.
		attrs := map[string]string{
			"email": e2eEmail,
			"name":  e2eDisplayName,
		}
		accessToken, err := issuer.IssueAccessToken(e2eUserID, "privasys-platform", roles, attrs)
		if err != nil {
			log.Printf("e2e: access token issuance failed: %v", err)
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}

		// Issue ID token.
		idToken, err := issuer.IssueIDToken(tokens.IDTokenClaims{
			Subject:          e2eUserID,
			Email:            e2eEmail,
			Name:             e2eDisplayName,
			AttestationLevel: "e2e",
			Audience:         clientID,
			AuthTime:         time.Now(),
		})
		if err != nil {
			log.Printf("e2e: ID token issuance failed: %v", err)
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessToken,
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}
}

// ensureE2EUser creates the e2e test user if it doesn't exist.
func ensureE2EUser(db *store.DB) error {
	_, err := db.Exec(
		`INSERT INTO users (user_id, display_name, email) VALUES (?, ?, ?)
		 ON CONFLICT(user_id) DO NOTHING`,
		e2eUserID, e2eDisplayName, e2eEmail,
	)
	return err
}
