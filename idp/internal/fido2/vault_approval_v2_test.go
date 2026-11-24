// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package fido2

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/vaultbinding"
)

const (
	memberA = "1111111111111111111111111111111111111111111111111111111111111111"
	memberB = "2222222222222222222222222222222222222222222222222222222222222222"
)

// The vault's own vector: an update_policy bound to the digest of the policy
// as sent. What this builds must be that text's digest, field for field.
func TestBindVaultV2MatchesTheVault(t *testing.T) {
	raw, err := os.ReadFile("../vaultbinding/testdata/v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Binding struct {
			Approver, Handle, Nonce, Op, Target string
			Exp                                 int64
			Members                             []string
			PolicyVersion                       uint64 `json:"policy_version"`
			VaultOp                             string `json:"vault_op"`
		} `json:"binding_v2_update_policy_with_pd"`
		Policy struct {
			PolicyAsSent string `json:"policy_as_sent"`
		} `json:"policy_digest"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	sub := strings.TrimPrefix(v.Binding.Approver, "oidc:0:")
	f := vaultV2Fields{
		Operation: v.Binding.Op, Handle: v.Binding.Handle, Target: v.Binding.Target,
		PolicyVersion: v.Binding.PolicyVersion, Members: []string{v.Binding.Members[1], v.Binding.Members[0]},
		NewPolicy: json.RawMessage(v.Policy.PolicyAsSent),
	}
	target, err := checkVaultV2Fields(f, false)
	if err != nil {
		t.Fatal(err)
	}
	fields, _, vaultOp, err := bindVaultV2(sub, f, target, v.Binding.Nonce, v.Binding.Exp)
	if err != nil {
		t.Fatal(err)
	}
	if vaultOp != v.Binding.VaultOp {
		t.Fatalf("vault_op %s, want %s", vaultOp, v.Binding.VaultOp)
	}
	// The fields returned rebuild the same text.
	back := vaultbinding.BindingV2{Members: fields.Members, Op: vaultbinding.BindingOp(fields.Op), Handle: fields.Handle,
		Target: fields.Target, PolicyVersion: fields.PolicyVersion, Approver: fields.Approver, Nonce: fields.Nonce, Exp: fields.Exp}
	if got, _ := back.VaultOp(); got != vaultOp {
		t.Fatalf("the returned fields rebuild %s, not %s", got, vaultOp)
	}
	if fields.HolderHead != "-" || fields.Approver != v.Binding.Approver {
		t.Fatalf("fields: %+v", fields)
	}
}

func TestCheckVaultV2Fields(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	policy := json.RawMessage(`{"a":1}`)
	pd, _ := vaultbinding.PolicyDigestJSON(policy)
	base := vaultV2Fields{Handle: "vaults/x/k", Members: []string{memberA, memberB}}
	with := func(edit func(*vaultV2Fields)) vaultV2Fields { f := base; edit(&f); return f }

	ok := []struct {
		name    string
		f       vaultV2Fields
		inBatch bool
		target  string
	}{
		{"promote", with(func(f *vaultV2Fields) { f.Operation, f.Target = "promote", hex }), false, hex},
		{"export, dash", with(func(f *vaultV2Fields) { f.Operation, f.Target = "export", "-" }), false, ""},
		{"delete", with(func(f *vaultV2Fields) { f.Operation = "delete" }), false, ""},
		{"update_policy", with(func(f *vaultV2Fields) { f.Operation, f.Target, f.NewPolicy = "update_policy", pd, policy }), false, pd},
		{"delete_after in a batch", with(func(f *vaultV2Fields) { f.Operation, f.Target, f.TTLSeconds = "delete_after", hex, 7200 }), true, hex},
	}
	for _, c := range ok {
		if got, err := checkVaultV2Fields(c.f, c.inBatch); err != nil || got != c.target {
			t.Errorf("%s: target %q, err %v", c.name, got, err)
		}
	}

	bad := []struct {
		name    string
		f       vaultV2Fields
		inBatch bool
	}{
		{"no handle", with(func(f *vaultV2Fields) { f.Operation, f.Target, f.Handle = "promote", hex, "" }), false},
		{"no members", with(func(f *vaultV2Fields) { f.Operation, f.Target, f.Members = "promote", hex, nil }), false},
		{"promote without a target", with(func(f *vaultV2Fields) { f.Operation = "promote" }), false},
		{"export with a target", with(func(f *vaultV2Fields) { f.Operation, f.Target = "export", hex }), false},
		{"delete with a target", with(func(f *vaultV2Fields) { f.Operation, f.Target = "delete", hex }), false},
		{"update without a policy", with(func(f *vaultV2Fields) { f.Operation, f.Target = "update_policy", pd }), false},
		{"update bound to another policy", with(func(f *vaultV2Fields) { f.Operation, f.Target, f.NewPolicy = "update_policy", hex, policy }), false},
		{"a policy on a promote", with(func(f *vaultV2Fields) { f.Operation, f.Target, f.NewPolicy = "promote", hex, policy }), false},
		{"a policy the vault would refuse", with(func(f *vaultV2Fields) {
			f.Operation, f.Target, f.NewPolicy = "update_policy", pd, json.RawMessage(`{"a":1.5}`)
		}), false},
		{"delete_after outside a batch", with(func(f *vaultV2Fields) { f.Operation, f.Target = "delete_after", hex }), false},
		{"delete_after beyond a day", with(func(f *vaultV2Fields) { f.Operation, f.Target, f.TTLSeconds = "delete_after", hex, 86401 }), true},
		{"a ttl on a promote", with(func(f *vaultV2Fields) { f.Operation, f.Target, f.TTLSeconds = "promote", hex, 60 }), true},
		{"a v1 operation name", with(func(f *vaultV2Fields) { f.Operation = "policy-update" }), false},
		{"create, not offered yet", with(func(f *vaultV2Fields) { f.Operation, f.Target = "create", hex }), false},
	}
	for _, c := range bad {
		if _, err := checkVaultV2Fields(c.f, c.inBatch); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestCheckVaultMemberIdentitiesCoversTheMembers(t *testing.T) {
	if err := checkVaultMemberIdentities([]string{memberA}, nil); err == nil {
		t.Error("no identities: accepted")
	}
	// An identity that does not agree with itself is refused whoever it names.
	bogus := []vaultbinding.VaultIdentity{{MemberID: memberA, MemberPublicKey: "04", QuoteB64: "AA"}}
	if err := checkVaultMemberIdentities([]string{memberA}, bogus); err == nil {
		t.Error("an inconsistent identity: accepted")
	}
}

// A delete_after whose successor is created (a migration or a rotation) needs
// no promote beside it: it names the successor, and the target is computed.
func TestCheckVaultV2DeleteAfterCreatedSuccessor(t *testing.T) {
	want, err := vaultbinding.DeleteAfterTarget("apps/x/data-v8", "")
	if err != nil {
		t.Fatal(err)
	}
	base := vaultV2Fields{Operation: "delete_after", Handle: "apps/x/data-v7", Members: []string{memberA}, SuccessorHandle: "apps/x/data-v8"}
	for _, inBatch := range []bool{false, true} {
		if got, err := checkVaultV2Fields(base, inBatch); err != nil || got != want {
			t.Errorf("inBatch=%v: target %q, err %v", inBatch, got, err)
		}
	}
	given := base
	given.Target = want
	if got, err := checkVaultV2Fields(given, false); err != nil || got != want {
		t.Errorf("with the target stated: %q, %v", got, err)
	}
	bad := map[string]func(*vaultV2Fields){
		"its own successor":            func(f *vaultV2Fields) { f.SuccessorHandle = f.Handle },
		"a target for another":         func(f *vaultV2Fields) { f.Target = strings.Repeat("ab", 32) },
		"a successor with a line":      func(f *vaultV2Fields) { f.SuccessorHandle = "a\nb" },
		"held past the ordinary limit": func(f *vaultV2Fields) { f.TTLSeconds = 601 },
	}
	for name, edit := range bad {
		f := base
		edit(&f)
		if _, err := checkVaultV2Fields(f, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// update_policy_from binds the policy it replaces: the target is computed here
// from the two policies, as the vault's vector has it.
func TestCheckVaultV2UpdatePolicyFrom(t *testing.T) {
	raw, err := os.ReadFile("../vaultbinding/testdata/v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		From struct {
			Current string `json:"current_policy_as_get_policy_returns_it"`
			Target  string `json:"target"`
			VaultOp string `json:"vault_op"`
		} `json:"binding_v2_update_policy_from"`
		With struct {
			Approver, Handle, Nonce string
			Exp                     int64
			Members                 []string
			PolicyVersion           uint64 `json:"policy_version"`
		} `json:"binding_v2_update_policy_with_pd"`
		Policy struct {
			PolicyAsSent string `json:"policy_as_sent"`
		} `json:"policy_digest"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	f := vaultV2Fields{
		Operation: "update_policy_from", Handle: v.With.Handle, PolicyVersion: v.With.PolicyVersion, Members: v.With.Members,
		NewPolicy: json.RawMessage(v.Policy.PolicyAsSent), CurrentPolicy: json.RawMessage(v.From.Current),
	}
	target, err := checkVaultV2Fields(f, false)
	if err != nil || target != v.From.Target {
		t.Fatalf("target %q (%v), want %q", target, err, v.From.Target)
	}
	sub := strings.TrimPrefix(v.With.Approver, "oidc:0:")
	if _, _, vaultOp, err := bindVaultV2(sub, f, target, v.With.Nonce, v.With.Exp); err != nil || vaultOp != v.From.VaultOp {
		t.Fatalf("vault_op %q (%v), want %q", vaultOp, err, v.From.VaultOp)
	}
	bad := map[string]func(*vaultV2Fields){
		"no current policy":       func(f *vaultV2Fields) { f.CurrentPolicy = nil },
		"no new policy":           func(f *vaultV2Fields) { f.NewPolicy = nil },
		"a target for other ones": func(f *vaultV2Fields) { f.Target = strings.Repeat("ab", 32) },
	}
	for name, edit := range bad {
		g := f
		edit(&g)
		if _, err := checkVaultV2Fields(g, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := checkVaultV2Fields(f, true); err == nil {
		t.Error("in a batch: accepted")
	}
	plain := f
	plain.Operation = "update_policy"
	if _, err := checkVaultV2Fields(plain, false); err == nil {
		t.Error("a current policy on a plain update_policy: accepted")
	}
}
