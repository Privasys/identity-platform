// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import (
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/attributes"
)

// The rewrite is the only part of the migration that carries meaning, and the
// only part reachable without cgo (go-sqlite3 stubs out under CGO_ENABLED=0).
func TestRewriteGovSpellings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      []string
		want    string
		changed bool
	}{
		{
			name:    "the pre-split whitelist this migration exists for",
			in:      []string{"email", "birthdate", "nationality"},
			want:    "email birthdate_id nationality_id",
			changed: true,
		},
		{
			// One disclosure under two spellings collapses to the one that still
			// means what the registration meant. Keeping both would leave a
			// self-asserted answer available for a question the client asked a
			// passport.
			name:    "both spellings collapse to the government-backed one",
			in:      []string{"birthdate", "birthdate_id"},
			want:    "birthdate_id",
			changed: true,
		},
		{
			// given_name was self-asserted before the split and is self-asserted
			// after it. Rewriting it would take a free profile field a client
			// asked for and start charging it for a passport ceremony.
			name:    "keys that were always self-asserted are left alone",
			in:      []string{"email", "name", "given_name", "family_name", "picture"},
			want:    "email name given_name family_name picture",
			changed: false,
		},
		{
			name:    "a whitelist already on the new spelling is not touched",
			in:      []string{"email", "birthdate_id"},
			want:    "email birthdate_id",
			changed: false,
		},
		{
			name:    "order is preserved so a diff in the log reads as a rename",
			in:      []string{"nationality", "email", "birthdate"},
			want:    "nationality_id email birthdate_id",
			changed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := rewriteGovSpellings(tc.in)
			if strings.Join(got, " ") != tc.want {
				t.Errorf("rewrote %v to %v, want [%s]", tc.in, got, tc.want)
			}
			if changed != tc.changed {
				t.Errorf("changed = %v, want %v", changed, tc.changed)
			}
		})
	}
}

// The migration writes attribute keys into a table the IdP validates on every
// registration, so a target that is not canonical would leave a client whose
// whitelist can never be re-saved. The referential is the check because it is the
// same document /authorize resolves against.
func TestGovIDSpellingTargetsAreCanonicalGovKeys(t *testing.T) {
	for bare, gov := range govIDSpelling {
		b, ok := attributes.ByKey[bare]
		if !ok {
			t.Errorf("%q is not a canonical attribute", bare)
			continue
		}
		if b.IsGovVerified() {
			t.Errorf("%q still reads as government-backed; there is nothing to migrate away from", bare)
		}
		if b.GovKey != gov {
			t.Errorf("%q names %q as its government twin, not %q", bare, b.GovKey, gov)
		}
		g, ok := attributes.ByKey[gov]
		if !ok {
			t.Errorf("%q is not a canonical attribute", gov)
			continue
		}
		if !g.IsGovVerified() || !g.RequestOnly {
			t.Errorf("%q: gov=%v requestOnly=%v, want true/true", gov, g.IsGovVerified(), g.RequestOnly)
		}
	}
}
