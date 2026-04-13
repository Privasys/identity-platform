// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package store provides SQLite-backed persistence for the IdP.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

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
