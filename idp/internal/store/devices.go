// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import (
	"database/sql"
	"errors"
	"time"
)

// Devices: one holder, several phones.
//
// Every phone of a holder shares the wallet's seed, so the same identities, and
// registers its own passkey on each of them. A passkey carries a device tag,
// which the wallet derives per identity from a secret of that phone
// (HMAC(device secret, user_id)): tags of one phone on two identities are
// unrelated values, so the table still says nothing about which identities
// belong together. A wallet that knows a phone's secret (any phone of the same
// holder) can name that phone's passkey on any identity, which is how one phone
// revokes another.
//
// Push targets are kept per (identity, device tag), and a notification goes to
// every phone of the identity.

// ErrVersionConflict is returned by a versioned write whose expected version is
// not the stored one: another phone wrote first.
var ErrVersionConflict = errors.New("stored version differs from the expected one")

func migrateDevices(db *sql.DB) error {
	if !hasColumn(db, "credentials", "device_tag") {
		if _, err := db.Exec("ALTER TABLE credentials ADD COLUMN device_tag TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	// push_tokens was keyed by user_id alone (one phone per identity). Rebuilt
	// once, keeping every row, as (user_id, device_tag) with '' for the rows
	// written before tags existed.
	if !hasColumn(db, "push_tokens", "device_tag") {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, q := range []string{
			`CREATE TABLE push_tokens_v2 (
				user_id    TEXT NOT NULL REFERENCES users(user_id),
				device_tag TEXT NOT NULL DEFAULT '',
				push_token TEXT NOT NULL,
				enc_pub    TEXT NOT NULL DEFAULT '',
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (user_id, device_tag)
			)`,
			`INSERT INTO push_tokens_v2 (user_id, device_tag, push_token, enc_pub, updated_at)
				SELECT user_id, '', push_token, enc_pub, updated_at FROM push_tokens`,
			`DROP TABLE push_tokens`,
			`ALTER TABLE push_tokens_v2 RENAME TO push_tokens`,
		} {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	for _, t := range []string{"sovereign_backups", "identity_indexes"} {
		if !hasColumn(db, t, "version") {
			if _, err := db.Exec("ALTER TABLE " + t + " ADD COLUMN version INTEGER NOT NULL DEFAULT 1"); err != nil {
				return err
			}
		}
	}
	return nil
}

func hasColumn(db *sql.DB, table, column string) bool {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt *string
		if rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk) == nil && name == column {
			return true
		}
	}
	return false
}

// --- Push targets ---

// PushTarget is one phone's way to be reached for an identity.
type PushTarget struct {
	Token  string
	EncPub string
}

// GetPushTargets returns every phone registered for a user.
func (db *DB) GetPushTargets(userID string) []PushTarget {
	rows, err := db.Query("SELECT push_token, enc_pub FROM push_tokens WHERE user_id = ? ORDER BY updated_at DESC", userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []PushTarget
	for rows.Next() {
		var t PushTarget
		if rows.Scan(&t.Token, &t.EncPub) == nil && t.Token != "" {
			out = append(out, t)
		}
	}
	return out
}

// GetPushTokens returns every push token registered for a user.
func (db *DB) GetPushTokens(userID string) []string {
	var out []string
	for _, t := range db.GetPushTargets(userID) {
		out = append(out, t.Token)
	}
	return out
}

// UpsertDevicePushTarget stores one phone's push token and sealing key for an
// identity. A tagged registration replaces the untagged row a wallet wrote
// before tags existed: that row was this phone's own (one wallet per identity
// until devices), and keeping it would deliver everything twice.
func (db *DB) UpsertDevicePushTarget(userID, deviceTag, pushToken, encPub string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if deviceTag != "" {
		if _, err := tx.Exec("DELETE FROM push_tokens WHERE user_id = ? AND device_tag = ''", userID); err != nil {
			return err
		}
	}
	// The same token under another tag of this identity is this phone again
	// (a reinstall makes a new device secret): one phone, one row.
	if _, err := tx.Exec("DELETE FROM push_tokens WHERE user_id = ? AND push_token = ? AND device_tag <> ?", userID, pushToken, deviceTag); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO push_tokens (user_id, device_tag, push_token, enc_pub, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, device_tag) DO UPDATE SET
			push_token = excluded.push_token,
			enc_pub = CASE WHEN excluded.enc_pub = '' THEN push_tokens.enc_pub ELSE excluded.enc_pub END,
			updated_at = CURRENT_TIMESTAMP
	`, userID, deviceTag, pushToken, encPub); err != nil {
		return err
	}
	return tx.Commit()
}

// --- Device tags on passkeys ---

// TagCredential records which phone holds a passkey, once: a tag already set is
// never replaced, so a session cannot move another phone's passkey under its
// own tag.
func (db *DB) TagCredential(userID, credentialID, deviceTag string) error {
	if deviceTag == "" {
		return nil
	}
	_, err := db.Exec(
		"UPDATE credentials SET device_tag = ? WHERE user_id = ? AND credential_id = ? AND device_tag = ''",
		deviceTag, userID, credentialID)
	return err
}

// RevokeDevice removes one phone from an identity: its passkeys, its push
// target and its refresh tokens' reach. Passkeys with no tag (written before
// tags existed) go too, except keepCredentialID, the revoking phone's own: an
// untagged passkey that is not the caller's belongs to a phone the holder no
// longer has in hand. Returns the removed credential ids, so the caller can end
// their wallet sessions.
func (db *DB) RevokeDevice(userID, deviceTag, keepCredentialID string) ([]string, error) {
	if deviceTag == "" {
		return nil, errors.New("device tag is required")
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`
		SELECT credential_id, device_tag FROM credentials
		 WHERE user_id = ? AND (device_tag = ? OR (device_tag = '' AND credential_id <> ?))`,
		userID, deviceTag, keepCredentialID)
	if err != nil {
		return nil, err
	}
	var ids []string
	untagged := false
	for rows.Next() {
		var id, tag string
		if err := rows.Scan(&id, &tag); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
		if tag == "" {
			untagged = true
		}
	}
	rows.Close()
	for _, id := range ids {
		if _, err := tx.Exec("DELETE FROM credentials WHERE credential_id = ?", id); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec("DELETE FROM push_tokens WHERE user_id = ? AND device_tag = ?", userID, deviceTag); err != nil {
		return nil, err
	}
	if untagged {
		if _, err := tx.Exec("DELETE FROM push_tokens WHERE user_id = ? AND device_tag = ''", userID); err != nil {
			return nil, err
		}
	}
	return ids, tx.Commit()
}

// ReplaceIdentityRecoveryKey rotates an identity's recovery key. Only called
// after a signature by the current key, as part of revoking a phone: the
// revoked phone still holds the seed, and the new key is derived from a secret
// it never received.
func (db *DB) ReplaceIdentityRecoveryKey(userID string, publicKey []byte) error {
	_, err := db.Exec(`
		INSERT INTO identity_recovery_keys (user_id, public_key) VALUES (?, ?)
		ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key`,
		userID, publicKey)
	return err
}

// GrantEnrolment lets a new phone register a passkey on an existing identity
// for the next hour, WITHOUT the recovery's removal of the other phones'
// passkeys. It rides recovery_requests with its own status, which the takeover
// gate in fido2/register/begin accepts alongside 'completed'.
func (db *DB) GrantEnrolment(requestID, userID string) error {
	_, err := db.Exec(
		`INSERT INTO recovery_requests (request_id, user_id, code_verified, status, expires_at)
		 VALUES (?, ?, TRUE, 'enrol', ?)`,
		requestID, userID, time.Now().Add(time.Hour))
	return err
}

// --- Versioned blobs ---

// versionedTables are the per-account encrypted blobs several phones write.
var versionedTables = map[string]bool{"sovereign_backups": true, "identity_indexes": true}

// PutVersioned writes a blob when the stored version is expect (0: no blob
// yet), and returns the new version. expect < 0 writes unconditionally, for
// wallets that send no version.
func (db *DB) PutVersioned(table, userID, blob string, expect int64) (int64, error) {
	if !versionedTables[table] {
		return 0, errors.New("unknown table")
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRow("SELECT version FROM "+table+" WHERE user_id = ?", userID).Scan(&current)
	switch {
	case err == sql.ErrNoRows:
		current = 0
	case err != nil:
		return 0, err
	}
	if expect >= 0 && expect != current {
		return current, ErrVersionConflict
	}
	next := current + 1
	if _, err := tx.Exec(`
		INSERT INTO `+table+` (user_id, blob, version, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET blob = excluded.blob, version = excluded.version, updated_at = CURRENT_TIMESTAMP`,
		userID, blob, next); err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

// GetVersioned returns a blob and its version, "" and 0 when none.
func (db *DB) GetVersioned(table, userID string) (string, int64, error) {
	if !versionedTables[table] {
		return "", 0, errors.New("unknown table")
	}
	var blob string
	var v int64
	err := db.QueryRow("SELECT blob, version FROM "+table+" WHERE user_id = ?", userID).Scan(&blob, &v)
	if err == sql.ErrNoRows {
		return "", 0, nil
	}
	return blob, v, err
}

// ValidDeviceTag reports whether s has the shape of a device tag: base64url,
// 16 to 64 characters (the wallet sends 22, 16 bytes).
func ValidDeviceTag(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// GetDevicePushTargets returns one phone's push target for a user.
func (db *DB) GetDevicePushTargets(userID, deviceTag string) []PushTarget {
	var t PushTarget
	if db.QueryRow("SELECT push_token, enc_pub FROM push_tokens WHERE user_id = ? AND device_tag = ?", userID, deviceTag).Scan(&t.Token, &t.EncPub) != nil || t.Token == "" {
		return nil
	}
	return []PushTarget{t}
}

// CountDevices returns how many phones hold a passkey on a user: one per
// device tag, and one for untagged passkeys (a phone from before tags).
func (db *DB) CountDevices(userID string) (int, error) {
	var tagged, untagged int
	err := db.QueryRow(`SELECT COUNT(DISTINCT CASE WHEN device_tag <> '' THEN device_tag END),
		COALESCE(MAX(CASE WHEN device_tag = '' THEN 1 ELSE 0 END), 0) FROM credentials WHERE user_id = ?`, userID).Scan(&tagged, &untagged)
	return tagged + untagged, err
}

// MaxDevices is how many phones one holder may have.
const MaxDevices = 5

// DeviceLimitReached reports whether a passkey for deviceTag would add a
// sixth phone to userID. A phone already there is never refused.
func (db *DB) DeviceLimitReached(userID, deviceTag string) (bool, error) {
	if deviceTag != "" {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM credentials WHERE user_id = ? AND device_tag = ?", userID, deviceTag).Scan(&n); err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	count, err := db.CountDevices(userID)
	return count >= MaxDevices, err
}
