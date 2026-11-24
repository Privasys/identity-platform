// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package fido2

import (
	"testing"

	"github.com/Privasys/idp/internal/tokens"
)

// An approval's token carries the audience its vaults accept: a requested
// platform audience, the default when none is asked for, never another.
func TestVaultApprovalAudience(t *testing.T) {
	tokens.SetPlatformAudiences([]string{"privasys-platform-test"})
	defer tokens.SetPlatformAudiences(nil)

	for _, c := range []struct {
		req, def, want string
		ok             bool
	}{
		{"", "privasys-platform", "privasys-platform", true},
		{"", "", "", true},
		{"privasys-platform-test", "privasys-platform", "privasys-platform-test", true},
		{"privasys-platform", "privasys-platform", "privasys-platform", true},
		{"attestation-server", "privasys-platform", "", false},
		{"privasys-vault-keycreate", "privasys-platform", "", false},
	} {
		got, err := vaultApprovalAudience(c.req, c.def)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("vaultApprovalAudience(%q, %q) = %q, %v", c.req, c.def, got, err)
		}
	}
}
