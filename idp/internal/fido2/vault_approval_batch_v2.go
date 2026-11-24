// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package fido2

// A batch whose entries are binding v2 operations on keys owned through an
// issuer: one tap, one token per entry.
//
// The batch id is unchanged (computeVaultBatchBinding): the v1 batch text,
// over each entry's v2 vault_op. A vault never sees it; each vault sees only
// its entry's token.
//
// A v2 batch may hold a delete_after: the delete of the old key of a migrate
// or upgrade, approved in the same tap as its successor's promote, and good
// for longer than the batch so it can be presented once the migrate or
// upgrade has succeeded. It is accepted only beside that promote.

import (
	"errors"
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"

	"github.com/Privasys/idp/internal/vaultbinding"
)

// validateVaultBatchV2 checks a requested v2 batch and returns its entries in
// canonical order. Export and plain delete stay one approval each.
func validateVaultBatchV2(label string, entries []vaultBatchEntry, ids []vaultbinding.VaultIdentity) ([]vaultBatchEntry, error) {
	if err := validateVaultBatchLabel(label, len(entries)); err != nil {
		return nil, err
	}
	out := make([]vaultBatchEntry, len(entries))
	copy(out, entries)
	seen := make(map[string]bool, len(out))
	successors := map[string]bool{}
	for i := range out {
		e := &out[i]
		if !utf8.ValidString(e.Handle) {
			return nil, fmt.Errorf("entry %d: handle must be valid text", i)
		}
		for _, r := range e.Handle {
			if unicode.IsSpace(r) || vaultBatchHiddenRune(r) {
				return nil, fmt.Errorf("entry %d: handle must not contain spaces, control, format or bidirectional characters", i)
			}
		}
		switch vaultbinding.BindingOp(e.Operation) {
		case vaultbinding.BindPromote, vaultbinding.BindUpdatePolicy, vaultbinding.BindRevokePending, vaultbinding.BindDeleteAfter:
		default:
			return nil, fmt.Errorf("entry %d: operation %q cannot be batched", i, e.Operation)
		}
		target, err := checkVaultV2Fields(e.v2Fields(), true)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %v", i, err)
		}
		if err := checkVaultMemberIdentities(e.Members, ids); err != nil {
			return nil, fmt.Errorf("entry %d: %v", i, err)
		}
		if e.SuccessorHandle != "" && e.Operation != string(vaultbinding.BindDeleteAfter) {
			return nil, fmt.Errorf("entry %d: successor_handle is for delete_after only", i)
		}
		e.Target = target
		// What the wallet shows as the bound value.
		e.MeasurementDigest = target
		if e.Operation == string(vaultbinding.BindPromote) {
			t, err := vaultbinding.DeleteAfterTarget(e.Handle, target)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %v", i, err)
			}
			successors[t] = true
		}
		key := e.Operation + " " + e.Handle
		if seen[key] {
			return nil, fmt.Errorf("entry %d: %s appears twice", i, key)
		}
		seen[key] = true
		e.Nonce, e.VaultOp, e.Binding = "", "", nil
		e.Context.Summary = clipSummary(e.Context.Summary)
	}
	for i := range out {
		if out[i].Operation == string(vaultbinding.BindDeleteAfter) && out[i].SuccessorHandle == "" && !successors[out[i].Target] {
			return nil, fmt.Errorf("entry %d: delete_after needs successor_handle, or the promote of its successor in the same batch", i)
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Handle != out[b].Handle {
			return out[a].Handle < out[b].Handle
		}
		return out[a].Operation < out[b].Operation
	})
	return out, nil
}

// bindVaultBatchV2 gives every entry its nonce, expiry and binding, and
// returns the batch id. Every entry expires with the batch, except a
// delete_after, which lives for its own ttl from now.
func bindVaultBatchV2(sub, label string, now, exp int64, entries []vaultBatchEntry, newNonce func() (string, error)) (string, [32]byte, error) {
	for i := range entries {
		nonce, err := newNonce()
		if err != nil {
			return "", [32]byte{}, err
		}
		e := &entries[i]
		entryExp := exp
		if e.Operation == string(vaultbinding.BindDeleteAfter) {
			ttl := e.TTLSeconds
			if ttl <= 0 {
				ttl = vaultV2DeleteAfterDefaultTTL
			}
			if entryExp = now + ttl; entryExp < exp {
				// Never shorter than the tap it is approved in.
				entryExp = exp
			}
		}
		fields, _, vaultOp, err := bindVaultV2(sub, e.v2Fields(), e.Target, nonce, entryExp)
		if err != nil {
			return "", [32]byte{}, errors.New("entry " + e.Handle + ": " + err.Error())
		}
		e.Nonce, e.VaultOp, e.Binding = nonce, vaultOp, &fields
	}
	batch := computeVaultBatchBinding(label, exp, entries)
	return bindingID(batch), batch, nil
}
