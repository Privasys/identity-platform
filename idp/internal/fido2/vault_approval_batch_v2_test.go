// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package fido2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/vaultbinding"
)

// testVaultIdentity builds an identity that agrees with itself: a v3 SGX
// quote whose report data commits to the member id and billing id.
func testVaultIdentity(t *testing.T, seed byte) vaultbinding.VaultIdentity {
	t.Helper()
	pub := append([]byte{0x04}, make([]byte, 64)...)
	for i := 1; i < len(pub); i++ {
		pub[i] = seed
	}
	id, err := vaultbinding.MemberID(pub)
	if err != nil {
		t.Fatal(err)
	}
	billing := strings.Repeat("b", 64)
	mrenclave := strings.Repeat("47", 32)
	quote := make([]byte, 48+384+16)
	binary.LittleEndian.PutUint16(quote[0:2], 3)
	mr, _ := hex.DecodeString(mrenclave)
	copy(quote[48+64:], mr)
	rd := vaultbinding.IdentityReportData(id, billing)
	copy(quote[48+320:], rd[:])
	out := vaultbinding.VaultIdentity{
		MemberID: id, MemberPublicKey: hex.EncodeToString(pub), BillingID: billing,
		MRENCLAVE: mrenclave, QuoteB64: base64.RawURLEncoding.EncodeToString(quote),
	}
	if err := out.CheckConsistent(); err != nil {
		t.Fatalf("test identity: %v", err)
	}
	return out
}

func testNonce() func() (string, error) {
	n := byte(0)
	return func() (string, error) {
		n++
		b := make([]byte, 16)
		b[0] = n
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
}

func TestVaultBatchV2MigrateInOneTap(t *testing.T) {
	a, b := testVaultIdentity(t, 1), testVaultIdentity(t, 2)
	ids := []vaultbinding.VaultIdentity{a, b}
	members := []string{a.MemberID, b.MemberID}
	profile := strings.Repeat("ab", 32)
	after, err := vaultbinding.DeleteAfterTarget("apps/x/data-v2", profile)
	if err != nil {
		t.Fatal(err)
	}
	in := []vaultBatchEntry{
		{Operation: "promote", Handle: "apps/x/data-v2", Target: profile, PolicyVersion: 1, Members: members},
		{Operation: "delete_after", Handle: "apps/x/data-v1", Target: after, PolicyVersion: 7, Members: members, TTLSeconds: 7200},
	}
	entries, err := validateVaultBatchV2("Upgrade x", in, ids)
	if err != nil {
		t.Fatal(err)
	}
	const now, exp = int64(1_800_000_000), int64(1_800_000_300)
	batchID, sum, err := bindVaultBatchV2("user-1", "Upgrade x", now, exp, entries, testNonce())
	if err != nil {
		t.Fatal(err)
	}
	if batchID != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("batch id is not the batch binding")
	}

	var promote, del *vaultBatchEntry
	for i := range entries {
		switch entries[i].Operation {
		case "promote":
			promote = &entries[i]
		case "delete_after":
			del = &entries[i]
		}
	}
	// The promote expires with the batch; the delete outlives it by its ttl.
	if promote.Binding.Exp != exp || promote.tokenExp(exp) != exp {
		t.Errorf("promote exp %d", promote.Binding.Exp)
	}
	if del.Binding.Exp != now+7200 || del.tokenExp(exp) != now+7200 {
		t.Errorf("delete_after exp %d, want %d", del.Binding.Exp, now+7200)
	}
	// Each entry's vault_op is its v2 binding's digest, rebuilt from the fields returned.
	for _, e := range entries {
		back := vaultbinding.BindingV2{Members: e.Binding.Members, Op: vaultbinding.BindingOp(e.Binding.Op),
			Handle: e.Binding.Handle, Target: e.Binding.Target, PolicyVersion: e.Binding.PolicyVersion,
			Approver: e.Binding.Approver, Nonce: e.Binding.Nonce, Exp: e.Binding.Exp}
		if got, _ := back.VaultOp(); got != e.VaultOp {
			t.Errorf("%s: fields rebuild %s, not %s", e.Operation, got, e.VaultOp)
		}
		if e.Binding.Approver != "oidc:0:user-1" {
			t.Errorf("approver %q", e.Binding.Approver)
		}
	}
	// The batch id is the v1 batch text over the v2 vault_ops, with the batch's expiry.
	want := sha256.Sum256([]byte("privasys-vault-approval-batch-v1\nUpgrade x\n1800000300\n2\n" +
		entries[0].Operation + " " + entries[0].VaultOp + "\n" + entries[1].Operation + " " + entries[1].VaultOp))
	if sum != want {
		t.Error("batch binding is not the v1 batch text over the entries")
	}
}

func TestVaultBatchV2DeleteAfterDefaultsToAnHour(t *testing.T) {
	a := testVaultIdentity(t, 1)
	profile := strings.Repeat("ab", 32)
	after, _ := vaultbinding.DeleteAfterTarget("k2", profile)
	entries, err := validateVaultBatchV2("L", []vaultBatchEntry{
		{Operation: "promote", Handle: "k2", Target: profile, Members: []string{a.MemberID}},
		{Operation: "delete_after", Handle: "k1", Target: after, Members: []string{a.MemberID}},
	}, []vaultbinding.VaultIdentity{a})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bindVaultBatchV2("u", "L", 1000, 1300, entries, testNonce()); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Operation == "delete_after" && e.Binding.Exp != 1000+3600 {
			t.Errorf("delete_after exp %d, want %d", e.Binding.Exp, 1000+3600)
		}
	}
}

func TestVaultBatchV2Refusals(t *testing.T) {
	a, b := testVaultIdentity(t, 1), testVaultIdentity(t, 2)
	ids := []vaultbinding.VaultIdentity{a}
	m := []string{a.MemberID}
	hex64 := strings.Repeat("ab", 32)
	after, _ := vaultbinding.DeleteAfterTarget("k2", hex64)
	policy := json.RawMessage(`{"a":1}`)
	pd, _ := vaultbinding.PolicyDigestJSON(policy)
	promote := vaultBatchEntry{Operation: "promote", Handle: "k2", Target: hex64, Members: m}

	if _, err := validateVaultBatchV2("L", []vaultBatchEntry{promote,
		{Operation: "update_policy", Handle: "k3", Target: pd, NewPolicy: policy, Members: m}}, ids); err != nil {
		t.Errorf("promote with a policy update: %v", err)
	}

	bad := map[string][]vaultBatchEntry{
		"a delete_after with no promote of its successor": {{Operation: "delete_after", Handle: "k1", Target: after, Members: m}},
		"a delete_after for another successor": {promote,
			{Operation: "delete_after", Handle: "k1", Target: strings.Repeat("cd", 32), Members: m}},
		"an export":                        {{Operation: "export", Handle: "k1", Members: m}},
		"a plain delete":                   {{Operation: "delete", Handle: "k1", Members: m}},
		"a v1 app-policy":                  {{Operation: "app-policy", Handle: "app:x:policy", Target: hex64, Members: m}},
		"a member with no identity":        {{Operation: "promote", Handle: "k2", Target: hex64, Members: []string{a.MemberID, b.MemberID}}},
		"the same operation twice":         {promote, promote},
		"a ttl on a promote":               {{Operation: "promote", Handle: "k2", Target: hex64, Members: m, TTLSeconds: 60}},
		"a policy update bound to another": {{Operation: "update_policy", Handle: "k3", Target: hex64, NewPolicy: policy, Members: m}},
		"a handle with a space":            {{Operation: "promote", Handle: "k 2", Target: hex64, Members: m}},
	}
	for name, entries := range bad {
		if _, err := validateVaultBatchV2("L", entries, ids); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := validateVaultBatchV2(" L", []vaultBatchEntry{promote}, ids); err == nil {
		t.Error("a padded label: accepted")
	}
	if _, err := validateVaultBatchV2("L", nil, ids); err == nil {
		t.Error("an empty batch: accepted")
	}
}

func TestVaultBatchV2DeleteAfterCreatedSuccessor(t *testing.T) {
	a := testVaultIdentity(t, 1)
	ids := []vaultbinding.VaultIdentity{a}
	m := []string{a.MemberID}
	entries, err := validateVaultBatchV2("Rotate", []vaultBatchEntry{
		{Operation: "delete_after", Handle: "k/v7", SuccessorHandle: "k/v8", Members: m},
	}, ids)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := vaultbinding.DeleteAfterTarget("k/v8", "")
	if entries[0].Target != want {
		t.Fatalf("target %q, want %q", entries[0].Target, want)
	}
	if _, _, err := bindVaultBatchV2("u", "Rotate", 1000, 1300, entries, testNonce()); err != nil {
		t.Fatal(err)
	}
	// Its successor exists already, so it expires with the batch.
	if entries[0].Binding.Target != want || entries[0].Binding.Exp != 1300 {
		t.Fatalf("binding %+v", entries[0].Binding)
	}
	if _, err := validateVaultBatchV2("L", []vaultBatchEntry{
		{Operation: "delete_after", Handle: "k/v7", SuccessorHandle: "k/v8", Members: m, TTLSeconds: 601},
	}, ids); err == nil {
		t.Error("a created-successor delete held past the ordinary limit: accepted")
	}
	if _, err := validateVaultBatchV2("L", []vaultBatchEntry{
		{Operation: "promote", Handle: "k2", Target: strings.Repeat("ab", 32), Members: m, SuccessorHandle: "k3"},
	}, ids); err == nil {
		t.Error("a successor on a promote: accepted")
	}
}
