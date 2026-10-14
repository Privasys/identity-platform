// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package admin

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/Privasys/idp/internal/tokens"
)

// Subjects for an operator migration.
//
// Every client sees its own subject for a person (internal/tokens/subject.go),
// derived one way. The IdP keeps no map back from a subject to an account, and
// no endpoint answers that question: a flow that must act on a subject an app
// hands back goes through a row the holder made for that app (a session, a
// consent, a relationship). What remains here is the FORWARD derivation an
// operator needs once, when a client moves to its own subjects and its data
// must be re-keyed. Admin token only.

const maxSubjectBatch = 500

// HandleSubjectsFor serves POST /admin/subjects/for
// {"client_id": "...", "accounts": ["..."]} → {"subjects": {"<account>": "<sub>"}}:
// the subject each account will have at a client that has its own.
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
