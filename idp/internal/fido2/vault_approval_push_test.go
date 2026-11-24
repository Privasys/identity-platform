// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

import (
	"strings"
	"testing"
)

// A push body names a key by its owner-given name, never by the key vault's id
// or a user's subject: the push crosses third-party push infrastructure.
func TestShortHandleNamesKeysNotIds(t *testing.T) {
	cases := map[string]string{
		"vaults/6f186e39-1111-2222-3333-444455556666/card1":    "key card1",
		"vaults/6f186e39-1111-2222-3333-444455556666/card1/v2": "key card1",
		"users/r2C7Km0Lsubject/home-check-1123":                "secret home-check-1123",
		"apps.privasys.org/0123456789abcdef/dek":               "app 01234567",
		"vaults/6f186e39-1111-2222-3333-444455556666":          "your key",
		"users/r2C7Km0Lsubject/":                               "your key",
		"":                                                     "your app",
	}
	for handle, want := range cases {
		if got := shortHandle(handle); got != want {
			t.Errorf("shortHandle(%q) = %q, want %q", handle, got, want)
		}
		if strings.Contains(shortHandle(handle), "6f186e39") || strings.Contains(shortHandle(handle), "r2C7Km0L") {
			t.Errorf("shortHandle(%q) leaks an id", handle)
		}
	}
	long := "vaults/x/" + strings.Repeat("n", 100)
	if r := []rune(shortHandle(long)); len(r) != len("key ")+maxPushNameRunes {
		t.Errorf("long name not clipped: %d runes", len(r))
	}
}
