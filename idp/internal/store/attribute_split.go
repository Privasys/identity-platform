// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/Privasys/idp/internal/attributes"
)

// The keys whose BARE spelling stopped meaning "a government document said so".
//
// This is a record of one release, not a restatement of the referential: it is
// the set of keys that were minted government-backed and became dual, so a
// registration that named them meant the passport reading and nothing else.
// given_name, family_name and picture were self-asserted from the start and must
// NOT appear here — rewriting one of those would take a free profile field a
// client asked for and start charging it for a passport disclosure.
var govIDSpelling = map[string]string{
	"birthdate":   "birthdate_id",
	"nationality": "nationality_id",
}

// migrateAttributeAssuranceSplit rewrites every client's required_attributes
// whitelist from the bare spelling of a newly-dual key to the '_id' spelling
// that still carries government assurance.
//
// The whitelist is a ceiling AND, for a request-only key, the registration-time
// half of naming it (see namedByRegistration in the oidc package), so a rewritten
// entry keeps a client receiving exactly the disclosure it received before: same
// scope, same one enclave-signed value, same one charge. Leaving it alone would
// hand an identity-scope client a self-asserted birth date where a passport used
// to answer, which is a security regression rather than a pricing change.
//
// Clients that declare NO whitelist need no migration: naming attributes is now
// mandatory (see validateRequiredAttributes), so such a row requests nothing and
// there is no assurance to preserve. They are logged because that is a change in
// what they receive, and only re-registering with a whitelist restores it.
func migrateAttributeAssuranceSplit(db *sql.DB) error {
	return applyOnce(db, "clients_gov_id_spelling_split", func(tx *sql.Tx) error {
		for bare, gov := range govIDSpelling {
			a, ok := attributes.ByKey[gov]
			if !ok || !a.IsGovVerified() {
				return fmt.Errorf("attribute split: %q is not a government-backed key in the referential", gov)
			}
			if b, ok := attributes.ByKey[bare]; !ok || b.GovKey != gov {
				return fmt.Errorf("attribute split: %q does not name %q as its government twin", bare, gov)
			}
		}

		rows, err := tx.Query("SELECT client_id, required_attributes FROM clients")
		if err != nil {
			return err
		}
		type rewrite struct{ clientID, before, after string }
		var rewrites []rewrite
		var unscoped []string
		for rows.Next() {
			var clientID, raw string
			if err := rows.Scan(&clientID, &raw); err != nil {
				rows.Close()
				return err
			}
			var attrs []string
			if err := json.Unmarshal([]byte(raw), &attrs); err != nil || len(attrs) == 0 {
				unscoped = append(unscoped, clientID)
				continue
			}
			if next, changed := rewriteGovSpellings(attrs); changed {
				encoded, err := json.Marshal(next)
				if err != nil {
					rows.Close()
					return err
				}
				rewrites = append(rewrites, rewrite{clientID, strings.Join(attrs, " "), string(encoded)})
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, r := range rewrites {
			if _, err := tx.Exec("UPDATE clients SET required_attributes = ? WHERE client_id = ?", r.after, r.clientID); err != nil {
				return err
			}
			log.Printf("attribute split: client %s required_attributes [%s] -> %s", r.clientID, r.before, r.after)
		}
		if len(unscoped) > 0 {
			sort.Strings(unscoped)
			log.Printf("attribute split: %d client(s) declare no required_attributes and now receive NO attributes; "+
				"naming them is mandatory, so each must be re-registered with the whitelist it needs: %s",
				len(unscoped), strings.Join(unscoped, ", "))
		}
		return nil
	})
}

// rewriteGovSpellings replaces the bare spellings with their government-backed
// twins, preserving order and collapsing a client that named both: the two were
// one disclosure under two names, so keeping both would leave the self-asserted
// key behind as a second, weaker answer to the same question.
func rewriteGovSpellings(attrs []string) ([]string, bool) {
	out := make([]string, 0, len(attrs))
	seen := make(map[string]bool, len(attrs))
	changed := false
	for _, a := range attrs {
		if gov, ok := govIDSpelling[a]; ok {
			a, changed = gov, true
		}
		if seen[a] {
			changed = true
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out, changed
}

// applyOnce runs a data migration the first time it is seen and records that it
// ran, in the same transaction as its effects.
//
// Schema migrations here are idempotent by construction (ADD COLUMN behind a
// PRAGMA check), but a data migration cannot be: it rewrites rows that the
// application is free to rewrite back. Re-running the assurance split on every
// boot would take a whitelist deliberately naming the self-asserted key and
// silently promote it to the paid one.
func applyOnce(db *sql.DB, name string, fn func(*sql.Tx) error) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS applied_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return err
	}
	var done int
	if err := db.QueryRow("SELECT COUNT(*) FROM applied_migrations WHERE name = ?", name).Scan(&done); err != nil {
		return err
	}
	if done > 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return fmt.Errorf("migration %s: %w", name, err)
	}
	if _, err := tx.Exec("INSERT INTO applied_migrations (name) VALUES (?)", name); err != nil {
		return err
	}
	return tx.Commit()
}
