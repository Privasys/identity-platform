// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Package vault issues vault key-creation grants (see the key-creation-grants
// design). A grant lets a caller that holds key material but is not the owner
// create a key on the vault in a single call: the grant names the owner and
// carries the full policy, and the vault binds it to the caller's attested
// app-id (OID 3.6) or a holder-of-key cnf.
package vault

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

const (
	appScopePrefix   = "apps.privasys.org/"
	userScopePrefix  = "users/"
	vaultScopePrefix = "vaults/"
	// platformManagerRole gates app-scoped grants: only an account holding the
	// platform control-plane manager role may mint a grant naming an arbitrary
	// owner. This is checked against the account's granted roles in the DB, NOT
	// the bearer token's audience-filtered `roles` claim - so it is unaffected by
	// whatever audience the caller minted its token with (the platform may serve
	// many audiences; this authority is always the canonical platform one).
	platformManagerRole = "privasys-platform:manager"
	defaultTTLSeconds   = 300
	maxTTLSeconds       = 900
)

type grantRequest struct {
	Scope      string          `json:"scope"`
	Owner      string          `json:"owner"` // required for app-scoped grants
	KeyType    string          `json:"key_type"`
	Exportable bool            `json:"exportable"`
	Policy     json.RawMessage `json:"policy"`
	CnfX5tS256 string          `json:"cnf_x5t_s256"` // holder-of-key, required for user-scoped grants
	TTLSeconds int64           `json:"ttl_seconds"`
}

// HandleKeyCreationGrant handles POST /vault/key-creation-grant.
//
// Auth: Authorization: Bearer <IdP access token>. The owner and the
// authorisation rule are selected by the requested scope:
//
//   - apps.privasys.org/<app-id>: the caller must carry the platform manager
//     role (the service account). owner is taken from the request. The vault
//     binds the grant to the app's attested app-id (OID 3.6 == <app-id>), so
//     only the real app TEE can spend it.
//   - users/<sub>: the caller's own sub must equal <sub>; owner is that sub.
//     A holder-of-key cnf is required (binds the grant to the caller's cert).
//   - vaults/<vault-id>: a key in a user-facing vault. The caller must carry the
//     platform manager role (the control plane mints these after verifying vault
//     membership); owner is taken from the request and a holder-of-key cnf binds
//     the grant to the creating agent.
func HandleKeyCreationGrant(iss *tokens.Issuer, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := bearerClaims(r, iss)
		if err != nil {
			errorJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		callerSub, _ := claims["sub"].(string)

		var req grantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
			req.Scope == "" || req.KeyType == "" || len(req.Policy) == 0 {
			errorJSON(w, http.StatusBadRequest, "scope, key_type and policy are required")
			return
		}

		owner, err := authorize(&req, callerSub, db)
		if err != nil {
			errorJSON(w, http.StatusForbidden, err.Error())
			return
		}

		ttl := req.TTLSeconds
		if ttl <= 0 || ttl > maxTTLSeconds {
			ttl = defaultTTLSeconds
		}
		grant, err := iss.IssueKeyCreationGrant(tokens.KeyCreationGrant{
			Owner:      owner,
			Scope:      req.Scope,
			KeyType:    req.KeyType,
			Exportable: req.Exportable,
			Policy:     req.Policy,
			CnfX5tS256: req.CnfX5tS256,
			Exp:        time.Now().Unix() + ttl,
		})
		if err != nil {
			log.Printf("vault/key-creation-grant: issue: %v", err)
			errorJSON(w, http.StatusInternalServerError, "grant issuance failed")
			return
		}
		log.Printf("vault: key-creation grant issued (owner=%s scope=%s)", owner, req.Scope)
		writeJSON(w, map[string]interface{}{"grant": grant})
	}
}

// authorize validates the request against the caller and returns the owner the
// grant must name.
func authorize(req *grantRequest, callerSub string, db *store.DB) (string, error) {
	switch {
	case strings.HasPrefix(req.Scope, appScopePrefix):
		if !accountHasRole(db, callerSub, platformManagerRole) {
			return "", errForbidden("app-scoped grants require the platform manager role")
		}
		if req.Owner == "" {
			return "", errForbidden("owner is required for an app-scoped grant")
		}
		return req.Owner, nil

	case strings.HasPrefix(req.Scope, userScopePrefix):
		sub := strings.TrimPrefix(req.Scope, userScopePrefix)
		if sub == "" || sub != callerSub {
			return "", errForbidden("a user-scoped grant must name the caller's own sub")
		}
		if req.CnfX5tS256 == "" {
			return "", errForbidden("a user-scoped grant requires a holder-of-key cnf")
		}
		return sub, nil

	case strings.HasPrefix(req.Scope, vaultScopePrefix):
		// A key inside a user-facing vault. The platform control plane (manager
		// role) mints these, having verified the caller's membership of the
		// vault's billing account; the owner is the vault's owner and a
		// holder-of-key cnf binds the grant to the agent that creates the key.
		// The policy (which may grant ExportKey to a Tee principal) is authored
		// by the control plane and signed here verbatim.
		if !accountHasRole(db, callerSub, platformManagerRole) {
			return "", errForbidden("vault-scoped grants require the platform manager role")
		}
		if req.Owner == "" {
			return "", errForbidden("owner is required for a vault-scoped grant")
		}
		if req.CnfX5tS256 == "" {
			return "", errForbidden("a vault-scoped grant requires a holder-of-key cnf")
		}
		return req.Owner, nil

	default:
		return "", errForbidden("unsupported scope")
	}
}

func bearerClaims(r *http.Request, iss *tokens.Issuer) (map[string]interface{}, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, errForbidden("missing bearer token")
	}
	return iss.VerifyAccessToken(strings.TrimPrefix(auth, "Bearer "))
}

// accountHasRole reports whether the account `sub` has been granted `role`,
// read from the DB (the source of truth) rather than the bearer token's
// audience-filtered `roles` claim - so it holds regardless of which audience
// the caller's token was minted for.
func accountHasRole(db *store.DB, sub, role string) bool {
	if sub == "" {
		return false
	}
	roles, err := db.GetRoles(sub)
	if err != nil {
		return false
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

type apiError struct{ msg string }

func (e apiError) Error() string       { return e.msg }
func errForbidden(msg string) apiError { return apiError{msg: msg} }

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func errorJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
