// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package admin

import "testing"

// TestAppRoleRegex pins the exact role shape /admin/app-roles may manage:
// only privasys-platform:app:<uuid>:owner|admin. In particular it must
// reject platform roles — the endpoint is scoped so the management service
// can sync app teams without being able to grant itself platform power.
func TestAppRoleRegex(t *testing.T) {
	const id = "f555f319-bfa9-4fc0-bcae-2c8c714fb31a"
	cases := map[string]bool{
		"privasys-platform:app:" + id + ":owner": true,
		"privasys-platform:app:" + id + ":admin": true,
		// Wrong tier.
		"privasys-platform:app:" + id + ":viewer": false,
		// Platform roles must never be manageable here.
		"privasys-platform:admin":   false,
		"privasys-platform:manager": false,
		// Wrong namespace prefix (would not surface on platform-audience
		// tokens anyway — filterRolesByAudience drops it).
		"app:" + id + ":owner": false,
		// Malformed UUIDs.
		"privasys-platform:app:not-a-uuid:owner": false,
		"privasys-platform:app::admin":           false,
		// Uppercase UUID (roles are stored verbatim; enforce canonical form).
		"privasys-platform:app:F555F319-BFA9-4FC0-BCAE-2C8C714FB31A:owner": false,
	}
	for role, want := range cases {
		if got := appRoleRegex.MatchString(role); got != want {
			t.Errorf("appRoleRegex(%q) = %v, want %v", role, got, want)
		}
	}
}
