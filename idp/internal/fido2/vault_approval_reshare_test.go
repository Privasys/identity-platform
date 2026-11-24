// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package fido2

import (
	"encoding/json"
	"strings"
	"testing"
)

// A reshare approval carries the resharing-context inputs to the wallet, which
// recomputes measurement_digest from them; no other operation carries them.
func TestReshareContextReachesTheWallet(t *testing.T) {
	base := vaultApprovalSummary{Operation: "reshare", Handle: "vaults/x/k"}
	got := base.withReshare("reshare", strings.Repeat("09", 32), "a:1,b:2,c:3", "2", "1,3", "AQEB")
	js, _ := json.Marshal(got)
	for _, want := range []string{
		`"target_mrenclave":"` + strings.Repeat("09", 32) + `"`,
		`"target_vaults":"a:1,b:2,c:3"`,
		`"threshold":"2"`,
		`"helpers":"1,3"`,
		`"public_key":"AQEB"`,
	} {
		if !strings.Contains(string(js), want) {
			t.Errorf("summary %s lacks %s", js, want)
		}
	}

	other := vaultApprovalSummary{Operation: "promote"}.withReshare("promote", "m", "v", "2", "1", "k")
	js, _ = json.Marshal(other)
	if strings.Contains(string(js), "target_") || strings.Contains(string(js), "threshold") {
		t.Errorf("a promote carries reshare fields: %s", js)
	}
}

// A field too long is refused, never clipped: a clipped value could not
// recompute the digest.
func TestReshareContextFits(t *testing.T) {
	if !reshareContextFits("a", strings.Repeat("x", maxReshareFieldBytes)) {
		t.Error("a field at the limit was refused")
	}
	if reshareContextFits("a", strings.Repeat("x", maxReshareFieldBytes+1)) {
		t.Error("a field over the limit was accepted")
	}
}
