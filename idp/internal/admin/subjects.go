// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package admin

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// Subject resolution for the platform.
//
// Every client sees its own subject for a person (internal/tokens/subject.go).
// The platform keys accounts, ownership and billing by the account, and some
// of what reaches it names a person by an app's subject: a spend token's
// payer, a usage record's caller. These endpoints let the platform turn those
// into accounts, and give an operator migration the subjects a client will
// see once it leaves the legacy shared mode. Admin token only: what they
// return is exactly the linkage relying parties must never hold.

const maxSubjectBatch = 500

// HandleResolveSubjects serves POST /admin/subjects/resolve
// {"subs": ["..."]} → {"accounts": {"<sub>": "<account>"}}.
// A sub the IdP has no record of is left out; the caller treats it as an
// account id (the legacy shared mode issues those).
func HandleResolveSubjects(db *store.DB, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAdmin(w, r, adminToken) {
			return
		}
		var req struct {
			Subs []string `json:"subs"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || len(req.Subs) == 0 {
			writeError(w, http.StatusBadRequest, "subs is required")
			return
		}
		if len(req.Subs) > maxSubjectBatch {
			writeError(w, http.StatusBadRequest, "too many subs in one call")
			return
		}
		out := make(map[string]string, len(req.Subs))
		for _, sub := range req.Subs {
			if account, ok := db.ResolveSubject(sub); ok {
				out[sub] = account
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
	}
}

// HandleSubjectsFor serves POST /admin/subjects/for
// {"client_id": "...", "accounts": ["..."]} → {"subjects": {"<account>": "<sub>"}}:
// the subject each account has at that client in its own mode, whatever mode
// it is in now. For re-keying a client's data before it is moved off the
// legacy shared mode.
func HandleSubjectsFor(issuer *tokens.Issuer, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAdmin(w, r, adminToken) {
			return
		}
		var req struct {
			ClientID string   `json:"client_id"`
			Accounts []string `json:"accounts"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.ClientID == "" || len(req.Accounts) == 0 {
			writeError(w, http.StatusBadRequest, "client_id and accounts are required")
			return
		}
		if len(req.Accounts) > maxSubjectBatch {
			writeError(w, http.StatusBadRequest, "too many accounts in one call")
			return
		}
		out := make(map[string]string, len(req.Accounts))
		for _, account := range req.Accounts {
			out[account] = issuer.SubjectFor(account, req.ClientID)
		}
		writeJSON(w, http.StatusOK, map[string]any{"subjects": out})
	}
}
