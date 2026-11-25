// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package fido2

import (
	"regexp"
	"testing"
)

// A token issued for a rules change must not also be an export approval.
//
// "export" binds the empty measurement slot and "promote" a 64-hex digest. A
// rules change binds its own name, so its binding equals neither for the same
// key, policy version, nonce and expiry.
func TestPolicyUpdateBindsNothingAnotherOperationBinds(t *testing.T) {
	const handle, nonce = "apps.privasys.org/app/storage-kek/v4", "bm9uY2U"
	const version, exp = uint64(7), int64(1_800_000_000)

	rules := computeVaultApprovalBinding(handle, vaultPolicyUpdateSlot, version, nonce, exp)
	export := computeVaultApprovalBinding(handle, "", version, nonce, exp)
	if rules == export {
		t.Fatal("a rules-change approval binds what an export binds")
	}
	if vaultPolicyUpdateSlot == "" {
		t.Fatal("the rules-change slot is the export slot")
	}
	// Never the shape of a promote's digest, whatever digest that is.
	if regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(vaultPolicyUpdateSlot) {
		t.Fatal("the rules-change slot has the shape of a promote digest")
	}
	// No line break: the binding text is line-separated, and a slot with one
	// could be made to read as other fields.
	if regexp.MustCompile(`[\r\n]`).MatchString(vaultPolicyUpdateSlot) {
		t.Fatal("the rules-change slot holds a line break")
	}
}
