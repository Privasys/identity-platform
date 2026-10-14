// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessions

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Relationship rows: one per (app subject, client), the only durable link an
// app has to a person once the IdP keeps no map from a subject back to an
// account. Written forward, at sign-in, when the IdP knows the account; read
// when an app hands its subject back (a notification to the holder). Deleted
// when the holder removes the app, never by a phone change: the relationship
// is the holder's, not the phone's.
//
// A row is not a reverse map: nothing derives it from a subject, and it
// exists only while the holder keeps the app.

// holderTouchEvery bounds the write per sign-in: last_seen_at moves at most
// this often for one pair, so a busy page costs no write at all.
const holderTouchEvery = time.Hour

func (s *Store) ensureHolders() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS app_holders (
			app_subject  TEXT NOT NULL,
			client_id    TEXT NOT NULL,
			user_id      TEXT NOT NULL,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (app_subject, client_id)
		);
		CREATE INDEX IF NOT EXISTS idx_app_holders_user ON app_holders(user_id, client_id);
	`)
	return err
}

// RecordHolder remembers that `userID` is `appSubject` at `clientID`. Called
// at every sign-in (code exchange, voucher allocation); cheap when the row
// exists and was seen within the hour.
func (s *Store) RecordHolder(appSubject, clientID, userID string) error {
	if appSubject == "" || clientID == "" || userID == "" {
		return errors.New("holders: subject, client and user are required")
	}
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO app_holders (app_subject, client_id, user_id, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(app_subject, client_id) DO UPDATE SET
			user_id = excluded.user_id,
			last_seen_at = excluded.last_seen_at
		WHERE app_holders.last_seen_at < ?`,
		appSubject, clientID, userID, now, now, now.Add(-holderTouchEvery))
	return err
}

// HolderOf returns the account behind the subject a client sees, while the
// relationship stands.
func (s *Store) HolderOf(appSubject, clientID string) (string, bool) {
	var userID string
	err := s.db.QueryRow(
		`SELECT user_id FROM app_holders WHERE app_subject = ? AND client_id = ?`,
		appSubject, clientID).Scan(&userID)
	if err != nil {
		return "", false
	}
	return userID, true
}

// RemoveHolder ends the relationship between an account and a client, and
// every session of that pair with it (the browsers the holder approved for
// that app end as signed-out). Returns how many sessions ended.
func (s *Store) RemoveHolder(userID, clientID string) (int, error) {
	if _, err := s.db.Exec(`DELETE FROM app_holders WHERE user_id = ? AND client_id = ?`, userID, clientID); err != nil {
		return 0, err
	}
	rows, err := s.db.Query(
		`SELECT sid FROM sessions WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL`,
		userID, clientID)
	if err != nil {
		return 0, err
	}
	var sids []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			rows.Close()
			return 0, err
		}
		sids = append(sids, sid)
	}
	rows.Close()
	n := 0
	for _, sid := range sids {
		if err := s.Revoke(sid); err != nil && !errors.Is(err, ErrNotFound) {
			return n, err
		}
		n++
		if s.onRevoke != nil {
			s.onRevoke(sid)
		}
	}
	return n, nil
}

// BackfillHolders writes a relationship row for every (account, client) pair
// that has a live session and none yet, deriving the subject forward. Run
// once at startup after the table is created; idempotent.
func (s *Store) BackfillHolders(subjectFor func(userID, clientID string) string) (int, error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT user_id, client_id FROM sessions
		  WHERE revoked_at IS NULL AND expires_at > ?`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	type pair struct{ user, client string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.user, &p.client); err != nil {
			rows.Close()
			return 0, err
		}
		pairs = append(pairs, p)
	}
	rows.Close()
	n := 0
	for _, p := range pairs {
		sub := subjectFor(p.user, p.client)
		if sub == "" {
			continue
		}
		var one int
		if err := s.db.QueryRow(`SELECT 1 FROM app_holders WHERE app_subject = ? AND client_id = ?`, sub, p.client).Scan(&one); err == nil {
			continue
		} else if !errors.Is(err, sql.ErrNoRows) {
			return n, err
		}
		if err := s.RecordHolder(sub, p.client, p.user); err != nil {
			return n, fmt.Errorf("backfill %s: %w", p.client, err)
		}
		n++
	}
	return n, nil
}

// ActiveAccount is the tokens.AccountResolver: the account behind a live
// session, or ok=false for a session that is unknown, revoked or expired.
func (s *Store) ActiveAccount(sid string) (string, bool) {
	sess, err := s.Get(sid)
	if err != nil || sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
		return "", false
	}
	return sess.UserID, true
}
