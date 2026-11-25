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
	// push_token_keys: the key each token's device proved itself with.
	// bind_pub, bound on a registration: the key it came with, and whether it
	// was signed by the token's proven key (recovery/pushbind.go).
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS push_token_keys (push_token TEXT PRIMARY KEY, bind_pub TEXT NOT NULL)"); err != nil {
		return err
	}
	if !hasColumn(db, "push_tokens", "bind_pub") {
		for _, q := range []string{
			"ALTER TABLE push_tokens ADD COLUMN bind_pub TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE push_tokens ADD COLUMN bound INTEGER NOT NULL DEFAULT 0",
		} {
			if _, err := db.Exec(q); err != nil {
				return err
			}
		}
	}
	// badge_off: a device that asked for no number on its icon (push/badge.go).
	if !hasColumn(db, "push_tokens", "badge_off") {
		if _, err := db.Exec("ALTER TABLE push_tokens ADD COLUMN badge_off INTEGER NOT NULL DEFAULT 0"); err != nil {
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

// SetPushBinding records the binding key a registration came with and whether
// the row is bound to it.
func (db *DB) SetPushBinding(userID, pushToken, bindPub string, bound bool) error {
	b := 0
	if bound {
		b = 1
	}
	_, err := db.Exec("UPDATE push_tokens SET bind_pub = ?, bound = ? WHERE user_id = ? AND push_token = ?", bindPub, b, userID, pushToken)
	return err
}

// PushTokenBindKey is the key a token's device proved itself with, or "" when
// none has.
func (db *DB) PushTokenBindKey(pushToken string) string {
	var k string
	db.QueryRow("SELECT bind_pub FROM push_token_keys WHERE push_token = ?", pushToken).Scan(&k)
	return k
}

// BindPushToken records the key a token's device answered a challenge with.
// It binds no registration by itself: each identity is bound by its own
// signature under this key. A registration made under an earlier key no
// longer is.
func (db *DB) BindPushToken(pushToken, bindPub string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO push_token_keys (push_token, bind_pub) VALUES (?, ?)
		ON CONFLICT(push_token) DO UPDATE SET bind_pub = excluded.bind_pub`, pushToken, bindPub); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE push_tokens SET bound = 0 WHERE push_token = ? AND bind_pub <> ?", pushToken, bindPub); err != nil {
		return err
	}
	return tx.Commit()
}

// SetPushBadge records whether a device takes a number on its icon. The
// choice is the device's, so it is set on every registration of its token.
func (db *DB) SetPushBadge(pushToken string, on bool) error {
	off := 1
	if on {
		off = 0
	}
	_, err := db.Exec("UPDATE push_tokens SET badge_off = ? WHERE push_token = ?", off, pushToken)
	return err
}

// BadgeTokens lists a user's push tokens that take a number on their icon:
// bound to their device, and not switched off there.
func (db *DB) BadgeTokens(userID string) []string {
	rows, err := db.Query("SELECT push_token FROM push_tokens WHERE user_id = ? AND badge_off = 0 AND bound = 1 AND push_token <> ''", userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			out = append(out, t)
		}
	}
	return out
}

// PushTokenUsers lists the users a push token is bound for: the identities
// one phone holds. Read when a count is needed and kept nowhere.
func (db *DB) PushTokenUsers(pushToken string) []string {
	rows, err := db.Query("SELECT DISTINCT user_id FROM push_tokens WHERE push_token = ? AND bound = 1", pushToken)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			out = append(out, u)
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
// longer has in hand. KeepAllUntagged ("*") leaves every untagged passkey
// alone: a phone removing itself does not speak for the others. Returns the
// removed credential ids, so the caller can end their wallet sessions.
func (db *DB) RevokeDevice(userID, deviceTag, keepCredentialID string) ([]string, error) {
	if deviceTag == "" {
		return nil, errors.New("device tag is required")
	}
	if deviceTag == AllOtherDevices {
		return db.revokeAllBut(userID, keepCredentialID)
	}
	untaggedToo := 1
	if keepCredentialID == KeepAllUntagged {
		untaggedToo = 0
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`
		SELECT credential_id, device_tag FROM credentials
		 WHERE user_id = ? AND (device_tag = ? OR (? = 1 AND device_tag = '' AND credential_id <> ?))`,
		userID, deviceTag, untaggedToo, keepCredentialID)
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

// AllOtherDevices, as RevokeDevice's deviceTag, removes every phone but the
// caller's: after a phrase recovery the holder has one phone, and a lost one may
// hold passkeys no list names.
const AllOtherDevices = "*"

func (db *DB) revokeAllBut(userID, keepCredentialID string) ([]string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT credential_id FROM credentials WHERE user_id = ? AND credential_id <> ?", userID, keepCredentialID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := tx.Exec("DELETE FROM credentials WHERE credential_id = ?", id); err != nil {
			return nil, err
		}
	}
	// The caller registers its own push target again with its next session.
	if _, err := tx.Exec("DELETE FROM push_tokens WHERE user_id = ?", userID); err != nil {
		return nil, err
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

// KeepAllUntagged, as RevokeDevice's keepCredentialID, leaves untagged passkeys alone.
const KeepAllUntagged = "*"

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

// PushPeer is another phone of a holder: the user it is registered for and its
// push token.
type PushPeer struct {
	UserID string
	Token  string
}

// GetPushPeers returns the other phones registered for any user that token is
// registered for, each token once, never the token itself. Bound rows only on
// both sides: a token someone merely claimed is nobody's other phone.
func (db *DB) GetPushPeers(token string) []PushPeer {
	rows, err := db.Query(`SELECT p2.user_id, p2.push_token FROM push_tokens p1
		JOIN push_tokens p2 ON p2.user_id = p1.user_id
		WHERE p1.push_token = ? AND p2.push_token <> ? AND p1.bound = 1 AND p2.bound = 1
		ORDER BY p2.updated_at DESC`, token, token)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []PushPeer
	for rows.Next() {
		var p PushPeer
		if rows.Scan(&p.UserID, &p.Token) == nil && p.Token != "" && !seen[p.Token] {
			seen[p.Token] = true
			out = append(out, p)
		}
	}
	return out
}
