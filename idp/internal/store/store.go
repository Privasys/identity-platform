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
func (db *DB) CreateServiceAccount(accountID, displayName, publicKeyPEM, keyID string) error {
	_, err := db.Exec(
		`INSERT INTO service_accounts (account_id, display_name, public_key, key_id) VALUES (?, ?, ?, ?)
		 ON CONFLICT(account_id) DO UPDATE SET display_name = excluded.display_name, public_key = excluded.public_key, key_id = excluded.key_id`,
		accountID, displayName, publicKeyPEM, keyID,
	)
	return err
}
