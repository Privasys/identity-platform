// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.
package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Deleting an account.
//
// The IdP keeps no link between a person's identities, or between an identity
// and the main account, so a deletion is a set of independent marks: one row
// per user_id ("delete this one at delete_at"), made by the wallet for each of
// its identities. Nothing here ties two rows together. When a row falls due,
// that user_id's data is deleted and each of its passkeys leaves a tombstone,
// so a phone that missed the news learns, from that passkey alone, that the
// account is gone.

// AccountDeletion is one user_id marked for deletion.
type AccountDeletion struct {
	UserID   string
	DeleteAt time.Time
	// Main is the wallet's main account (notices go to its push targets).
	Main bool
	// NotifyControlPlane is the privasys.id identity the deletion was asked
	// from: the control plane's account is keyed by its subject.
	NotifyControlPlane bool
	Reminded           bool
}

// Tombstone reasons.
const (
	TombstoneAccountDeleted = "account_deleted"
	TombstoneDeviceRemoved  = "device_removed"
)

// TombstoneTTL is how long a tombstone answers.
const TombstoneTTL = 90 * 24 * time.Hour

func migrateAccountDeletion(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS account_deletions (
			user_id     TEXT PRIMARY KEY,
			delete_at   DATETIME NOT NULL,
			main        INTEGER NOT NULL DEFAULT 0,
			notify_cp   INTEGER NOT NULL DEFAULT 0,
			reminded    INTEGER NOT NULL DEFAULT 0,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		-- One row per passkey, never grouped: credentials of different
		-- identities must stay unlinkable. cred_hash is an HMAC of the
		-- credential id under a server key.
		CREATE TABLE IF NOT EXISTS credential_tombstones (
			cred_hash    TEXT PRIMARY KEY,
			reason       TEXT NOT NULL,
			delete_after DATETIME NOT NULL
		);
	`)
	return err
}

// MarkAccountDeletion marks userID for deletion at deleteAt. Marking again
// keeps the earliest date and adds the flags.
func (db *DB) MarkAccountDeletion(d AccountDeletion) error {
	_, err := db.Exec(`
		INSERT INTO account_deletions (user_id, delete_at, main, notify_cp)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			delete_at = MIN(delete_at, excluded.delete_at),
			main      = MAX(main, excluded.main),
			notify_cp = MAX(notify_cp, excluded.notify_cp)`,
		d.UserID, d.DeleteAt.UTC(), b2i(d.Main), b2i(d.NotifyControlPlane))
	return err
}

// GetAccountDeletion returns userID's mark, nil when there is none.
func (db *DB) GetAccountDeletion(userID string) (*AccountDeletion, error) {
	d := &AccountDeletion{UserID: userID}
	var main, cp, rem int
	err := db.QueryRow(`SELECT delete_at, main, notify_cp, reminded FROM account_deletions WHERE user_id = ?`, userID).
		Scan(&d.DeleteAt, &main, &cp, &rem)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.Main, d.NotifyControlPlane, d.Reminded = main == 1, cp == 1, rem == 1
	d.DeleteAt = d.DeleteAt.UTC()
	return d, nil
}

// UnmarkAccountDeletion removes userID's mark; it reports whether there was one.
func (db *DB) UnmarkAccountDeletion(userID string) (*AccountDeletion, error) {
	d, err := db.GetAccountDeletion(userID)
	if err != nil || d == nil {
		return d, err
	}
	_, err = db.Exec(`DELETE FROM account_deletions WHERE user_id = ?`, userID)
	return d, err
}

// DueAccountDeletions lists marks whose date has passed.
func (db *DB) DueAccountDeletions(now time.Time) ([]AccountDeletion, error) {
	return db.listDeletions(`SELECT user_id, delete_at, main, notify_cp, reminded FROM account_deletions WHERE delete_at <= ? ORDER BY delete_at`, now.UTC())
}

// DeletionsToRemind lists main accounts within a day of deletion that have not
// had their reminder.
func (db *DB) DeletionsToRemind(now time.Time) ([]AccountDeletion, error) {
	return db.listDeletions(`SELECT user_id, delete_at, main, notify_cp, reminded FROM account_deletions WHERE main = 1 AND reminded = 0 AND delete_at <= ? ORDER BY delete_at`, now.Add(24*time.Hour).UTC())
}

// SetDeletionReminded records that the 1-day reminder went out.
func (db *DB) SetDeletionReminded(userID string) error {
	_, err := db.Exec(`UPDATE account_deletions SET reminded = 1 WHERE user_id = ?`, userID)
	return err
}

func (db *DB) listDeletions(q string, arg any) ([]AccountDeletion, error) {
	rows, err := db.Query(q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountDeletion
	for rows.Next() {
		var d AccountDeletion
		var main, cp, rem int
		if err := rows.Scan(&d.UserID, &d.DeleteAt, &main, &cp, &rem); err != nil {
			return nil, err
		}
		d.Main, d.NotifyControlPlane, d.Reminded = main == 1, cp == 1, rem == 1
		d.DeleteAt = d.DeleteAt.UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// TombstoneHash is the keyed hash a credential id is stored under.
func TombstoneHash(key []byte, credentialID string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("privasys-credential-tombstone/v1\x00"))
	m.Write([]byte(credentialID))
	return hex.EncodeToString(m.Sum(nil))
}

// AddTombstones records one row per credential id.
func (db *DB) AddTombstones(key []byte, credentialIDs []string, reason string, now time.Time) error {
	for _, id := range credentialIDs {
		if id == "" {
			continue
		}
		if _, err := db.Exec(`INSERT INTO credential_tombstones (cred_hash, reason, delete_after) VALUES (?, ?, ?)
			ON CONFLICT(cred_hash) DO UPDATE SET reason = excluded.reason, delete_after = excluded.delete_after`,
			TombstoneHash(key, id), reason, now.Add(TombstoneTTL).UTC()); err != nil {
			return err
		}
	}
	return nil
}

// TombstoneReason returns why a credential is gone, "" when it is not
// tombstoned (or its tombstone expired).
func (db *DB) TombstoneReason(key []byte, credentialID string, now time.Time) string {
	var reason string
	if err := db.QueryRow(`SELECT reason FROM credential_tombstones WHERE cred_hash = ? AND delete_after > ?`,
		TombstoneHash(key, credentialID), now.UTC()).Scan(&reason); err != nil {
		return ""
	}
	return reason
}

// CleanupTombstones drops expired tombstones.
func (db *DB) CleanupTombstones(now time.Time) error {
	_, err := db.Exec(`DELETE FROM credential_tombstones WHERE delete_after <= ?`, now.UTC())
	return err
}

// CredentialIDs lists userID's passkey ids.
func (db *DB) CredentialIDs(userID string) ([]string, error) {
	rows, err := db.Query(`SELECT credential_id FROM credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// deleteUserStatements remove everything held for one user_id, children
// before parents (foreign keys are enforced). Tables created by other
// packages are included: a missing table is skipped, not an error.
var deleteUserStatements = []string{
	`DELETE FROM recovery_approvals WHERE guardian_id = ?1 OR request_id IN (SELECT request_id FROM recovery_requests WHERE user_id = ?1)`,
	`DELETE FROM recovery_requests WHERE user_id = ?1`,
	`DELETE FROM guardians WHERE user_id = ?1 OR guardian_id = ?1`,
	`DELETE FROM guardian_invites WHERE user_id = ?1 OR guardian_id = ?1`,
	`DELETE FROM recovery_codes WHERE user_id = ?1`,
	`DELETE FROM sovereign_backups WHERE user_id = ?1`,
	`DELETE FROM grants_indexes WHERE user_id = ?1`,
	`DELETE FROM identity_indexes WHERE user_id = ?1`,
	`DELETE FROM identity_recovery_keys WHERE user_id = ?1`,
	`DELETE FROM session_encauth WHERE sid IN (SELECT sid FROM sessions WHERE user_id = ?1)`,
	`DELETE FROM sessions WHERE user_id = ?1`,
	`DELETE FROM app_holders WHERE user_id = ?1`,
	`DELETE FROM spend_consents WHERE user_id = ?1`,
	`DELETE FROM app_messages WHERE user_id = ?1`,
	`DELETE FROM refresh_tokens WHERE user_id = ?1`,
	`DELETE FROM roles WHERE user_id = ?1`,
	`DELETE FROM user_attributes WHERE user_id = ?1`,
	`DELETE FROM push_tickets WHERE user_id = ?1`,
	`DELETE FROM push_tokens WHERE user_id = ?1`,
	`DELETE FROM credentials WHERE user_id = ?1`,
	`DELETE FROM account_deletions WHERE user_id = ?1`,
	`DELETE FROM users WHERE user_id = ?1`,
}

// DeleteUserData removes every row held for userID in one transaction.
func (db *DB) DeleteUserData(userID string) error {
	if userID == "" {
		return errors.New("user id required")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range deleteUserStatements {
		if _, err := tx.Exec(q, userID); err != nil {
			if strings.Contains(err.Error(), "no such table") {
				continue
			}
			return err
		}
	}
	return tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
