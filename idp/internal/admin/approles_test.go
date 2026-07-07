// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package admin

import "testing"

// TestAppRoleRegex pins the exact role shape /admin/app-roles may manage:
// <audience>:app:<32-hex app id>:owner|admin|approver. In particular it must
// reject bare platform roles — the endpoint is scoped so the management
// service can sync app teams without being able to grant itself platform
// power.
func TestAppRoleRegex(t *testing.T) {
	// apps.id as raw hex (no dashes) — the OID 3.6 encoding.
	const id = "f555f319bfa94fc0bcae2c8c714fb31a"
	cases := map[string]bool{
		"privasys-platform:app:" + id + ":owner":     true,
		"privasys-platform:app:" + id + ":admin":     true,
		"attestation-server:app:" + id + ":approver": true,
		// Wrong tier.
		"privasys-platform:app:" + id + ":viewer": false,
		// Bare platform roles must never be manageable here.
		"privasys-platform:admin":         false,
		"privasys-platform:manager":       false,
		"privasys-platform:idp-app-roles": false,
		// Missing audience prefix (would not surface on any audience token).
		"app:" + id + ":owner": false,
		// Dashed-UUID form is rejected: the canonical app-id encoding is
		// 32-hex (byte-identical to OID 3.6 and the approver role).
		"privasys-platform:app:f555f319-bfa9-4fc0-bcae-2c8c714fb31a:owner": false,
		// Malformed ids.
		"privasys-platform:app:not-hex:owner": false,
		"privasys-platform:app::admin":        false,
		// Uppercase hex (roles are stored verbatim; enforce canonical form).
		"privasys-platform:app:F555F319BFA94FC0BCAE2C8C714FB31A:owner": false,
	}
	for role, want := range cases {
		if got := appRoleRegex.MatchString(role); got != want {
			t.Errorf("appRoleRegex(%q) = %v, want %v", role, got, want)
		}
	}
}
