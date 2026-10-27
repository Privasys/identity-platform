// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package fido2

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The summary an initiator attaches is a few lines on a phone card: trimmed,
// and clipped on a rune boundary when it runs long.
func TestClipSummary(t *testing.T) {
	if got := clipSummary("  Callers: any attested app  "); got != "Callers: any attested app" {
		t.Fatalf("trim: %q", got)
	}
	long := strings.Repeat("é", maxSummaryRunes+50)
	got := clipSummary(long)
	if n := utf8.RuneCountInString(got); n != maxSummaryRunes || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("clip: %d runes, valid %v", n, utf8.ValidString(got))
	}
}
