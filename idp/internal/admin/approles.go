// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package admin

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// App-scoped role management (POST/DELETE /admin/app-roles).
//
// The management service is the source of truth for per-app teams; when an
// owner/admin is added to or removed from an app it syncs the grant here so
// the role rides the caller's platform access token and enclaves can gate the
// app's configure surface statelessly (verify token, check role — no
// membership lists inside enclaves).
//
// Unlike the static-adminToken /admin/roles endpoints, this endpoint
// authenticates an IdP-issued access token whose roles include
// AppRoleAdminRole (granted to the management-service service account), and
// it can ONLY manage roles matching the app-role shape below — so the control
// plane never holds the global admin credential and cannot touch
// privasys-platform:* platform roles.

// AppRoleAdminRole authorizes a caller to grant/revoke app-scoped roles.
const AppRoleAdminRole = "privasys-platform:idp-app-roles"

// appRoleRegex pins the exact role shape this endpoint may manage:
// <audience>:app:<app-id-hex>:owner|admin|approver, where app-id-hex is the
// raw apps.id (32 lowercase hex chars, no dashes) — the same encoding the
// platform pins at OID 3.6 and already uses for the per-app approver role.
// The audience prefix is what filterRolesByAudience keys on: config roles are
// granted under privasys-platform so they ride platform-audience tokens;
// approver roles under the vault audience. The mandatory ":app:<hex>:" core
// plus the fixed tier suffix means the caller can never manage a bare
// platform role (privasys-platform:admin etc.) through this endpoint.
var appRoleRegex = regexp.MustCompile(
	`^[a-z0-9][a-z0-9-]*:app:[0-9a-f]{32}:(owner|admin|approver)$`)

// HandleGrantAppRole handles POST /admin/app-roles — grant an app-scoped role.
//
//	Request: {"user_id": "...", "role": "privasys-platform:app:<uuid>:admin"}
func HandleGrantAppRole(db *store.DB, issuer *tokens.Issuer, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := checkAppRoleCaller(w, r, issuer, adminToken)
		if !ok {
			return
		}
		userID, role, ok := readAppRoleBody(w, r)
		if !ok {
			return
		}
		if err := db.GrantRole(userID, role, caller); err != nil {
			log.Printf("admin/app-roles: grant failed: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to grant role")
			return
		}
		log.Printf("admin/app-roles: granted %q to user %s (by %s)", role, userID, caller)
		writeJSON(w, http.StatusOK, map[string]string{"status": "granted"})
	}
}

// HandleRevokeAppRole handles DELETE /admin/app-roles — revoke an app-scoped role.
func HandleRevokeAppRole(db *store.DB, issuer *tokens.Issuer, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := checkAppRoleCaller(w, r, issuer, adminToken)
		if !ok {
			return
		}
		userID, role, ok := readAppRoleBody(w, r)
		if !ok {
			return
		}
		if err := db.RevokeRole(userID, role); err != nil {
			log.Printf("admin/app-roles: revoke failed: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to revoke role")
			return
		}
		log.Printf("admin/app-roles: revoked %q from user %s (by %s)", role, userID, caller)
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}

// readAppRoleBody decodes and validates the {user_id, role} body shared by
// grant and revoke. The role MUST match the app-role shape — anything else
// (in particular platform roles) is rejected regardless of caller.
func readAppRoleBody(w http.ResponseWriter, r *http.Request) (userID, role string, ok bool) {
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return "", "", false
	}
	if req.UserID == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "user_id and role are required")
		return "", "", false
	}
	if !appRoleRegex.MatchString(req.Role) {
		writeError(w, http.StatusBadRequest,
			"role must match <audience>:app:<app-id-hex>:owner|admin|approver")
		return "", "", false
	}
	return req.UserID, req.Role, true
}

// checkAppRoleCaller authorizes the request: either the static admin token
// (operator break-glass), or an IdP-issued access token carrying
// AppRoleAdminRole (the management-service service account). Returns the
// caller identity for the grant audit column. Fails CLOSED when no admin
// token is configured — unlike checkAdmin's dev-mode allow-all, this
// endpoint manages authorization and must never be open.
func checkAppRoleCaller(w http.ResponseWriter, r *http.Request, issuer *tokens.Issuer, adminToken string) (string, bool) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || auth[:7] != "Bearer " {
		writeError(w, http.StatusUnauthorized, "bearer token required")
		return "", false
	}
	raw := auth[7:]

	if adminToken != "" && raw == adminToken {
		return "admin", true
	}

	claims, err := issuer.VerifyAccessToken(raw)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return "", false
	}
	sub, _ := claims["sub"].(string)
	if roles, ok := claims["roles"].([]interface{}); ok {
		for _, v := range roles {
			if s, ok := v.(string); ok && s == AppRoleAdminRole {
				return sub, true
			}
		}
	}
	writeError(w, http.StatusForbidden, AppRoleAdminRole+" role required")
	return "", false
}
