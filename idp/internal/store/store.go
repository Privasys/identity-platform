// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package store provides SQLite-backed persistence for the IdP.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps a SQLite connection with IdP-specific operations.
type DB struct {
	*sql.DB
}

// Open opens (or creates) the SQLite database at the given path and runs migrations.
func Open(path string) (*DB, error) {
	// Ensure directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &DB{db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		-- OIDC clients (relying parties that use this IdP).
		CREATE TABLE IF NOT EXISTS clients (
			client_id    TEXT PRIMARY KEY,
			client_name  TEXT NOT NULL,
			client_secret TEXT NOT NULL DEFAULT '',  -- bcrypt hash; empty = public client
			redirect_uris TEXT NOT NULL,  -- JSON array
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- FIDO2 users.
		CREATE TABLE IF NOT EXISTS users (
			user_id      TEXT PRIMARY KEY,  -- opaque ID (UUID)
			display_name TEXT NOT NULL DEFAULT '',
			email        TEXT NOT NULL DEFAULT '',
			avatar_url   TEXT NOT NULL DEFAULT '',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- FIDO2 credentials (one user can have multiple).
		CREATE TABLE IF NOT EXISTS credentials (
			credential_id TEXT PRIMARY KEY,  -- base64url-encoded
			user_id       TEXT NOT NULL REFERENCES users(user_id),
			public_key    BLOB NOT NULL,      -- COSE key bytes
			aaguid        TEXT NOT NULL DEFAULT '',
			sign_count    INTEGER NOT NULL DEFAULT 0,
			attestation_type TEXT NOT NULL DEFAULT 'none',
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

		-- User profile attributes (consented data).
		CREATE TABLE IF NOT EXISTS user_attributes (
			user_id TEXT NOT NULL REFERENCES users(user_id),
			key     TEXT NOT NULL,
			value   TEXT NOT NULL,
			source  TEXT NOT NULL DEFAULT 'manual',
			PRIMARY KEY (user_id, key)
		);

		-- User roles for authorization.
		CREATE TABLE IF NOT EXISTS roles (
			user_id    TEXT NOT NULL REFERENCES users(user_id),
			role       TEXT NOT NULL,
			scope      TEXT NOT NULL DEFAULT '*',
			granted_by TEXT NOT NULL DEFAULT '',
			granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, role)
		);

		-- Refresh tokens for long-lived sessions.
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token_hash  TEXT PRIMARY KEY,       -- SHA-256 hash of the token
			user_id     TEXT NOT NULL REFERENCES users(user_id),
			client_id   TEXT NOT NULL,
			scope       TEXT NOT NULL DEFAULT '',
			expires_at  DATETIME NOT NULL,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);

		-- Service accounts (machine users for JWT-bearer grant).
		CREATE TABLE IF NOT EXISTS service_accounts (
			account_id   TEXT PRIMARY KEY,
			display_name TEXT NOT NULL DEFAULT '',
			public_key   TEXT NOT NULL,          -- PEM-encoded RSA or EC public key
			key_id       TEXT NOT NULL DEFAULT '',
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- Email verification OTPs (short-lived).
		CREATE TABLE IF NOT EXISTS email_verifications (
			id          TEXT PRIMARY KEY,
			email       TEXT NOT NULL,
			code_hash   TEXT NOT NULL,          -- SHA-256 of 6-digit code
			expires_at  DATETIME NOT NULL,
			attempts    INTEGER NOT NULL DEFAULT 0,
			verified    BOOLEAN NOT NULL DEFAULT FALSE,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- Recovery codes (generated at FIDO2 registration, one-time use).
		CREATE TABLE IF NOT EXISTS recovery_codes (
			user_id     TEXT NOT NULL REFERENCES users(user_id),
			code_hash   TEXT NOT NULL,          -- SHA-256 of 16-char code
			used_at     DATETIME,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, code_hash)
		);

		-- Guardian relationships for social recovery.
		CREATE TABLE IF NOT EXISTS guardians (
			user_id        TEXT NOT NULL REFERENCES users(user_id),
			guardian_id    TEXT NOT NULL REFERENCES users(user_id),
			guardian_email TEXT NOT NULL,
			status         TEXT NOT NULL DEFAULT 'pending',
			threshold      INTEGER NOT NULL DEFAULT 1,
			invited_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			accepted_at    DATETIME,
			PRIMARY KEY (user_id, guardian_id)
		);

		-- Active recovery requests.
		CREATE TABLE IF NOT EXISTS recovery_requests (
			request_id          TEXT PRIMARY KEY,
			user_id             TEXT NOT NULL REFERENCES users(user_id),
			email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
			code_verified       BOOLEAN NOT NULL DEFAULT FALSE,
			guardians_required  INTEGER NOT NULL DEFAULT 0,
			guardians_approved  INTEGER NOT NULL DEFAULT 0,
			status              TEXT NOT NULL DEFAULT 'pending',
			new_credential_id   TEXT NOT NULL DEFAULT '',
			created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at          DATETIME NOT NULL
		);

		-- Per-guardian approval for recovery requests.
		CREATE TABLE IF NOT EXISTS recovery_approvals (
			request_id  TEXT NOT NULL REFERENCES recovery_requests(request_id),
			guardian_id TEXT NOT NULL REFERENCES users(user_id),
			approved    BOOLEAN NOT NULL,
			decided_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (request_id, guardian_id)
		);
	`)
	if err != nil {
		return err
	}

	// Migration: add client_secret column to existing databases.
	var hasSecret bool
	rows, err := db.Query("PRAGMA table_info(clients)")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue *string
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "client_secret" {
			hasSecret = true
		}
	}
	if !hasSecret {
		_, err = db.Exec("ALTER TABLE clients ADD COLUMN client_secret TEXT NOT NULL DEFAULT ''")
		if err != nil {
			return err
		}
	}

	// Migration: backfill users rows for existing service accounts so that
	// FK constraints (roles, etc.) work uniformly for all principal types.
	_, err = db.Exec(`
		INSERT INTO users (user_id, display_name)
		SELECT account_id, display_name FROM service_accounts
		WHERE account_id NOT IN (SELECT user_id FROM users)
	`)
	if err != nil {
		return err
	}

	return nil
}

// --- User operations ---

// UserInfo holds user details returned by ListUsers.
type UserInfo struct {
	UserID      string   `json:"user_id"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	CreatedAt   string   `json:"created_at"`
	Roles       []string `json:"roles"`
}

// ListUsers returns all users with their roles.
func (db *DB) ListUsers() ([]UserInfo, error) {
	rows, err := db.Query(`
		SELECT u.user_id, u.display_name, u.email, u.created_at
		FROM users u ORDER BY u.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserInfo
	for rows.Next() {
		var u UserInfo
		if err := rows.Scan(&u.UserID, &u.DisplayName, &u.Email, &u.CreatedAt); err != nil {
			continue
		}
		u.Roles = []string{}
		users = append(users, u)
	}

	// Fetch roles for all users.
	for i := range users {
		roles, err := db.GetRoles(users[i].UserID)
		if err == nil && roles != nil {
			users[i].Roles = roles
		}
	}

	if users == nil {
		users = []UserInfo{}
	}
	return users, nil
}

// --- Credential operations ---

// CredentialInfo holds credential details for device management.
type CredentialInfo struct {
	CredentialID    string `json:"credential_id"`
	AAGUID          string `json:"aaguid"`
	AttestationType string `json:"attestation_type"`
	SignCount       int    `json:"sign_count"`
	CreatedAt       string `json:"created_at"`
}

// ListCredentials returns all FIDO2 credentials for a user.
func (db *DB) ListCredentials(userID string) ([]CredentialInfo, error) {
	rows, err := db.Query(
		`SELECT credential_id, aaguid, attestation_type, sign_count, created_at
		 FROM credentials WHERE user_id = ? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []CredentialInfo
	for rows.Next() {
		var c CredentialInfo
		if err := rows.Scan(&c.CredentialID, &c.AAGUID, &c.AttestationType, &c.SignCount, &c.CreatedAt); err != nil {
			continue
		}
		creds = append(creds, c)
	}
	if creds == nil {
		creds = []CredentialInfo{}
	}
	return creds, nil
}

// RevokeCredential removes a specific FIDO2 credential for a user.
func (db *DB) RevokeCredential(userID, credentialID string) error {
	res, err := db.Exec(
		"DELETE FROM credentials WHERE user_id = ? AND credential_id = ?",
		userID, credentialID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

// --- Role operations ---

// GetRoles returns all roles for a user.
func (db *DB) GetRoles(userID string) ([]string, error) {
	rows, err := db.Query("SELECT role FROM roles WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			continue
		}
		roles = append(roles, role)
	}
	return roles, nil
}

// GrantRole assigns a role to a user.
func (db *DB) GrantRole(userID, role, grantedBy string) error {
	_, err := db.Exec(
		`INSERT INTO roles (user_id, role, granted_by) VALUES (?, ?, ?)
		 ON CONFLICT(user_id, role) DO NOTHING`,
		userID, role, grantedBy,
	)
	return err
}

// RevokeRole removes a role from a user.
func (db *DB) RevokeRole(userID, role string) error {
	_, err := db.Exec("DELETE FROM roles WHERE user_id = ? AND role = ?", userID, role)
	return err
}

// --- Refresh token operations ---

// StoreRefreshToken stores a hashed refresh token.
func (db *DB) StoreRefreshToken(tokenHash, userID, clientID, scope string, expiresAt time.Time) error {
	_, err := db.Exec(
		"INSERT INTO refresh_tokens (token_hash, user_id, client_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)",
		tokenHash, userID, clientID, scope, expiresAt,
	)
	return err
}

// ConsumeRefreshToken retrieves and deletes a refresh token (single-use rotation).
// Returns userID, clientID, scope.
func (db *DB) ConsumeRefreshToken(tokenHash string) (string, string, string, error) {
	var userID, clientID, scope string
	var expiresAt time.Time
	err := db.QueryRow(
		"SELECT user_id, client_id, scope, expires_at FROM refresh_tokens WHERE token_hash = ?",
		tokenHash,
	).Scan(&userID, &clientID, &scope, &expiresAt)
	if err != nil {
		return "", "", "", fmt.Errorf("refresh token not found: %w", err)
	}
	// Delete consumed token (rotation: caller issues a new one).
	db.Exec("DELETE FROM refresh_tokens WHERE token_hash = ?", tokenHash)
	if time.Now().After(expiresAt) {
		return "", "", "", fmt.Errorf("refresh token expired")
	}
	return userID, clientID, scope, nil
}

// CleanupExpiredRefreshTokens removes expired refresh tokens.
func (db *DB) CleanupExpiredRefreshTokens() {
	db.Exec("DELETE FROM refresh_tokens WHERE expires_at < ?", time.Now())
}

// --- Service account operations ---

// GetServiceAccount retrieves a service account by ID.
func (db *DB) GetServiceAccount(accountID string) (publicKeyPEM, keyID string, err error) {
	err = db.QueryRow(
		"SELECT public_key, key_id FROM service_accounts WHERE account_id = ?",
		accountID,
	).Scan(&publicKeyPEM, &keyID)
	return
}

// CreateServiceAccount stores a new service account.
// It also inserts a row into the users table so that foreign-key constraints
// (e.g. roles.user_id → users.user_id) are satisfied for service accounts.
func (db *DB) CreateServiceAccount(accountID, displayName, publicKeyPEM, keyID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Ensure a users row exists so FKs (roles, etc.) work for service accounts.
	_, err = tx.Exec(
		`INSERT INTO users (user_id, display_name) VALUES (?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET display_name = excluded.display_name`,
		accountID, displayName,
	)
	if err != nil {
		return err
	}

	_, err = tx.Exec(
		`INSERT INTO service_accounts (account_id, display_name, public_key, key_id) VALUES (?, ?, ?, ?)
		 ON CONFLICT(account_id) DO UPDATE SET display_name = excluded.display_name, public_key = excluded.public_key, key_id = excluded.key_id`,
		accountID, displayName, publicKeyPEM, keyID,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// --- Email verification operations ---

// StoreEmailVerification stores a hashed OTP for email verification.
func (db *DB) StoreEmailVerification(id, email, codeHash string, expiresAt time.Time) error {
	_, err := db.Exec(
		`INSERT INTO email_verifications (id, email, code_hash, expires_at) VALUES (?, ?, ?, ?)`,
		id, email, codeHash, expiresAt,
	)
	return err
}

// EmailVerificationRateCheck returns the number of OTPs sent to this email in the last hour.
func (db *DB) EmailVerificationRateCheck(email string) (int, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM email_verifications WHERE email = ? AND created_at > ?`,
		email, time.Now().Add(-1*time.Hour),
	).Scan(&count)
	return count, err
}

// VerifyEmailCode checks the OTP, increments attempts, and marks verified if correct.
// Returns the verification ID if successful.
func (db *DB) VerifyEmailCode(email, codeHash string) (string, error) {
	var id string
	var storedHash string
	var expiresAt time.Time
	var attempts int
	var verified bool

	err := db.QueryRow(
		`SELECT id, code_hash, expires_at, attempts, verified
		 FROM email_verifications
		 WHERE email = ? AND verified = FALSE
		 ORDER BY created_at DESC LIMIT 1`,
		email,
	).Scan(&id, &storedHash, &expiresAt, &attempts, &verified)
	if err != nil {
		return "", fmt.Errorf("no pending verification for this email")
	}
	if time.Now().After(expiresAt) {
		return "", fmt.Errorf("verification code expired")
	}
	if attempts >= 5 {
		return "", fmt.Errorf("too many verification attempts")
	}

	// Increment attempts.
	db.Exec("UPDATE email_verifications SET attempts = attempts + 1 WHERE id = ?", id)

	if storedHash != codeHash {
		return "", fmt.Errorf("invalid verification code")
	}

	// Mark verified.
	db.Exec("UPDATE email_verifications SET verified = TRUE WHERE id = ?", id)
	return id, nil
}

// IsEmailVerified checks if a verification ID is verified and not expired.
func (db *DB) IsEmailVerified(verificationID string) (string, bool) {
	var email string
	var verified bool
	var expiresAt time.Time
	err := db.QueryRow(
		"SELECT email, verified, expires_at FROM email_verifications WHERE id = ?",
		verificationID,
	).Scan(&email, &verified, &expiresAt)
	if err != nil || !verified {
		return "", false
	}
	// Extend validity window: verification good for 30 min after verified.
	if time.Now().After(expiresAt.Add(30 * time.Minute)) {
		return "", false
	}
	return email, true
}

// CleanupExpiredVerifications removes old email verification records.
func (db *DB) CleanupExpiredVerifications() {
	db.Exec("DELETE FROM email_verifications WHERE expires_at < ?", time.Now().Add(-1*time.Hour))
}

// --- Recovery code operations ---

// StoreRecoveryCodes stores hashed recovery codes for a user, replacing any existing ones.
func (db *DB) StoreRecoveryCodes(userID string, codeHashes []string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete existing codes.
	_, err = tx.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	for _, hash := range codeHashes {
		_, err = tx.Exec(
			"INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
			userID, hash,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// VerifyRecoveryCode checks if an unused recovery code matches for the user.
// Returns true and consumes the code if valid.
func (db *DB) VerifyRecoveryCode(userID, codeHash string) (bool, error) {
	res, err := db.Exec(
		"UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
		time.Now(), userID, codeHash,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// HasRecoveryCodes checks if a user has any unused recovery codes.
func (db *DB) HasRecoveryCodes(userID string) (int, error) {
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
		userID,
	).Scan(&count)
	return count, err
}

// --- Guardian operations ---

// AddGuardian creates a pending guardian invitation.
func (db *DB) AddGuardian(userID, guardianID, guardianEmail string, threshold int) error {
	_, err := db.Exec(
		`INSERT INTO guardians (user_id, guardian_id, guardian_email, status, threshold)
		 VALUES (?, ?, ?, 'pending', ?)
		 ON CONFLICT(user_id, guardian_id) DO UPDATE SET status = 'pending', threshold = excluded.threshold`,
		userID, guardianID, guardianEmail, threshold,
	)
	return err
}

// RespondToGuardianInvite lets a guardian accept or decline.
func (db *DB) RespondToGuardianInvite(userID, guardianID string, accept bool) error {
	status := "declined"
	if accept {
		status = "accepted"
	}
	res, err := db.Exec(
		`UPDATE guardians SET status = ?, accepted_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END
		 WHERE user_id = ? AND guardian_id = ? AND status = 'pending'`,
		status, accept, userID, guardianID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no pending invitation found")
	}
	return nil
}

// RemoveGuardian deletes a guardian relationship.
func (db *DB) RemoveGuardian(userID, guardianID string) error {
	_, err := db.Exec("DELETE FROM guardians WHERE user_id = ? AND guardian_id = ?", userID, guardianID)
	return err
}

// GuardianInfo holds guardian details.
type GuardianInfo struct {
	GuardianID    string `json:"guardian_id"`
	GuardianEmail string `json:"guardian_email"`
	Status        string `json:"status"`
	InvitedAt     string `json:"invited_at"`
	AcceptedAt    string `json:"accepted_at,omitempty"`
}

// ListGuardians returns all guardians for a user.
func (db *DB) ListGuardians(userID string) ([]GuardianInfo, int, error) {
	rows, err := db.Query(
		`SELECT guardian_id, guardian_email, status, invited_at, COALESCE(accepted_at, '')
		 FROM guardians WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var guardians []GuardianInfo
	for rows.Next() {
		var g GuardianInfo
		if err := rows.Scan(&g.GuardianID, &g.GuardianEmail, &g.Status, &g.InvitedAt, &g.AcceptedAt); err != nil {
			continue
		}
		guardians = append(guardians, g)
	}

	// Get threshold (same for all guardians of this user, stored on each row).
	var threshold int
	db.QueryRow("SELECT COALESCE(MAX(threshold), 0) FROM guardians WHERE user_id = ?", userID).Scan(&threshold)

	if guardians == nil {
		guardians = []GuardianInfo{}
	}
	return guardians, threshold, nil
}

// ListPendingGuardianInvites returns guardian invitations addressed to this user (as guardian).
func (db *DB) ListPendingGuardianInvites(guardianID string) ([]map[string]string, error) {
	rows, err := db.Query(
		`SELECT g.user_id, u.display_name, u.email, g.invited_at
		 FROM guardians g JOIN users u ON g.user_id = u.user_id
		 WHERE g.guardian_id = ? AND g.status = 'pending'`,
		guardianID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []map[string]string
	for rows.Next() {
		var userID, name, email, invitedAt string
		if err := rows.Scan(&userID, &name, &email, &invitedAt); err != nil {
			continue
		}
		invites = append(invites, map[string]string{
			"user_id":    userID,
			"name":       name,
			"email":      email,
			"invited_at": invitedAt,
		})
	}
	if invites == nil {
		invites = []map[string]string{}
	}
	return invites, nil
}

// GetAcceptedGuardianCount returns the number of accepted guardians and the threshold.
func (db *DB) GetAcceptedGuardianCount(userID string) (int, int, error) {
	var count, threshold int
	err := db.QueryRow(
		`SELECT COUNT(*), COALESCE(MAX(threshold), 0)
		 FROM guardians WHERE user_id = ? AND status = 'accepted'`,
		userID,
	).Scan(&count, &threshold)
	return count, threshold, err
}

// FindUserByEmail returns user_id for a user with a verified email attribute.
func (db *DB) FindUserByEmail(email string) (string, error) {
	var userID string
	err := db.QueryRow(
		"SELECT user_id FROM users WHERE email = ? LIMIT 1",
		email,
	).Scan(&userID)
	if err != nil {
		return "", fmt.Errorf("no user found with email %q", email)
	}
	return userID, nil
}

// --- Recovery request operations ---

// CreateRecoveryRequest starts a new recovery process.
func (db *DB) CreateRecoveryRequest(requestID, userID string, guardiansRequired int, expiresAt time.Time) error {
	_, err := db.Exec(
		`INSERT INTO recovery_requests (request_id, user_id, guardians_required, expires_at)
		 VALUES (?, ?, ?, ?)`,
		requestID, userID, guardiansRequired, expiresAt,
	)
	return err
}

// GetRecoveryRequest retrieves a recovery request.
type RecoveryRequest struct {
	RequestID         string
	UserID            string
	EmailVerified     bool
	CodeVerified      bool
	GuardiansRequired int
	GuardiansApproved int
	Status            string
	ExpiresAt         time.Time
}

func (db *DB) GetRecoveryRequest(requestID string) (*RecoveryRequest, error) {
	var r RecoveryRequest
	err := db.QueryRow(
		`SELECT request_id, user_id, email_verified, code_verified,
		        guardians_required, guardians_approved, status, expires_at
		 FROM recovery_requests WHERE request_id = ?`,
		requestID,
	).Scan(&r.RequestID, &r.UserID, &r.EmailVerified, &r.CodeVerified,
		&r.GuardiansRequired, &r.GuardiansApproved, &r.Status, &r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if time.Now().After(r.ExpiresAt) {
		db.Exec("UPDATE recovery_requests SET status = 'expired' WHERE request_id = ?", requestID)
		return nil, fmt.Errorf("recovery request expired")
	}
	return &r, nil
}

// UpdateRecoveryRequest updates fields on a recovery request.
func (db *DB) UpdateRecoveryRequest(requestID string, emailVerified, codeVerified bool) error {
	_, err := db.Exec(
		`UPDATE recovery_requests SET email_verified = ?, code_verified = ? WHERE request_id = ?`,
		emailVerified, codeVerified, requestID,
	)
	return err
}

// ApproveRecovery records a guardian's approval and increments the count.
func (db *DB) ApproveRecovery(requestID, guardianID string, approved bool) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO recovery_approvals (request_id, guardian_id, approved)
		 VALUES (?, ?, ?) ON CONFLICT(request_id, guardian_id) DO NOTHING`,
		requestID, guardianID, approved,
	)
	if err != nil {
		return err
	}

	if approved {
		_, err = tx.Exec(
			`UPDATE recovery_requests SET guardians_approved = guardians_approved + 1 WHERE request_id = ?`,
			requestID,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// CompleteRecovery marks the recovery as completed and revokes old credentials.
func (db *DB) CompleteRecovery(requestID, userID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Mark request completed.
	_, err = tx.Exec(
		"UPDATE recovery_requests SET status = 'completed' WHERE request_id = ?",
		requestID,
	)
	if err != nil {
		return err
	}

	// Revoke all existing FIDO2 credentials (new one will be registered).
	_, err = tx.Exec("DELETE FROM credentials WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	// Invalidate all existing recovery codes.
	_, err = tx.Exec("DELETE FROM recovery_codes WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	// Invalidate all refresh tokens.
	_, err = tx.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// CleanupExpiredRecoveryRequests removes expired recovery requests.
func (db *DB) CleanupExpiredRecoveryRequests() {
	db.Exec("DELETE FROM recovery_approvals WHERE request_id IN (SELECT request_id FROM recovery_requests WHERE expires_at < ?)", time.Now())
	db.Exec("DELETE FROM recovery_requests WHERE expires_at < ?", time.Now())
}

// ListActiveRecoveryRequests returns pending recovery requests for a user's guardians.
func (db *DB) ListActiveRecoveryRequests(guardianID string) ([]map[string]string, error) {
	rows, err := db.Query(
		`SELECT rr.request_id, rr.user_id, u.display_name, u.email, rr.created_at
		 FROM recovery_requests rr
		 JOIN users u ON rr.user_id = u.user_id
		 JOIN guardians g ON g.user_id = rr.user_id AND g.guardian_id = ?
		 WHERE rr.status = 'pending' AND rr.expires_at > ? AND g.status = 'accepted'
		 AND rr.request_id NOT IN (SELECT request_id FROM recovery_approvals WHERE guardian_id = ?)`,
		guardianID, time.Now(), guardianID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []map[string]string
	for rows.Next() {
		var requestID, userID, name, email, createdAt string
		if err := rows.Scan(&requestID, &userID, &name, &email, &createdAt); err != nil {
			continue
		}
		requests = append(requests, map[string]string{
			"request_id": requestID,
			"user_id":    userID,
			"name":       name,
			"email":      email,
			"created_at": createdAt,
		})
	}
	if requests == nil {
		requests = []map[string]string{}
	}
	return requests, nil
}
