// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package fido2

// Vault approvals on binding v2.
//
// A v2 approval names the vaults it is for (their member ids), so one made
// for a constellation cannot be spent on another, and it binds policy updates
// and deletes to their content. The caller sends the operation's fields; this
// adds who approves, a nonce and an expiry, and returns the fields, never a
// digest to trust: the caller and the wallet each rebuild the text.
//
// v1 requests (no binding_version, or 1) are untouched.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/Privasys/idp/internal/vaultbinding"
)

const (
	// vaultV2MaxMembers bounds a constellation named in one approval.
	vaultV2MaxMembers = 16
	// vaultV2MaxPolicyBytes bounds a new policy carried for update_policy.
	vaultV2MaxPolicyBytes = 64 << 10
	// vaultV2DeleteAfterDefaultTTL is a delete_after's lifetime when the
	// caller names none: long enough for an ordinary migration, far below the
	// vault's cap.
	vaultV2DeleteAfterDefaultTTL = int64(3600)
)

var vaultHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// vaultV2Fields is what a caller sends for one v2 operation.
type vaultV2Fields struct {
	Operation     string
	Handle        string
	Target        string // "-" or "" when the operation binds nothing more
	PolicyVersion uint64
	Members       []string
	IssuerIndex   uint32
	NewPolicy     json.RawMessage // update_policy only
	TTLSeconds    int64           // delete_after only
	// SuccessorHandle, on a delete_after, names a successor that is created
	// (a migration or a rotation), not promoted. The target is then computed
	// here, and the delete needs no promote beside it.
	SuccessorHandle string
}

// vaultBindingFields is the binding as it is returned and shown: every field
// of the text, so the receiver rebuilds it.
type vaultBindingFields struct {
	Members       []string `json:"members"`
	Op            string   `json:"op"`
	Handle        string   `json:"handle"`
	Target        string   `json:"target"`
	PolicyVersion uint64   `json:"policy_version"`
	Approver      string   `json:"approver"`
	HolderHead    string   `json:"holder_head"`
	Nonce         string   `json:"nonce"`
	Exp           int64    `json:"exp"`
}

// checkVaultV2Fields validates one operation's fields and returns its target
// as it stands in the binding ("" for none). inBatch allows delete_after,
// which exists only beside its successor's promote or creation.
func checkVaultV2Fields(f vaultV2Fields, inBatch bool) (string, error) {
	if f.Handle == "" || len(f.Handle) > vaultBatchMaxHandleBytes {
		return "", errors.New("handle required")
	}
	if len(f.Members) == 0 || len(f.Members) > vaultV2MaxMembers {
		return "", errors.New("members required")
	}
	target := f.Target
	if target == "-" {
		target = ""
	}
	hasPolicy := len(f.NewPolicy) > 0 && string(f.NewPolicy) != "null"
	if hasPolicy && f.Operation != string(vaultbinding.BindUpdatePolicy) {
		return "", errors.New("new_policy is for update_policy only")
	}
	if f.TTLSeconds != 0 && f.Operation != string(vaultbinding.BindDeleteAfter) {
		return "", errors.New("ttl_seconds on an entry is for delete_after only")
	}
	switch vaultbinding.BindingOp(f.Operation) {
	case vaultbinding.BindPromote, vaultbinding.BindReshare, vaultbinding.BindRevokePending:
		if !vaultHex64.MatchString(target) {
			return "", fmt.Errorf("target (64 lowercase hex) required for %s", f.Operation)
		}
	case vaultbinding.BindExport, vaultbinding.BindDelete:
		// A sealed export (a recipient digest as the target) arrives with the
		// wallet copy; until then export goes to the caller and binds nothing.
		if target != "" {
			return "", fmt.Errorf("%s takes no target", f.Operation)
		}
	case vaultbinding.BindUpdatePolicy:
		if !hasPolicy || len(f.NewPolicy) > vaultV2MaxPolicyBytes {
			return "", errors.New("new_policy required for update_policy")
		}
		pd, err := vaultbinding.PolicyDigestJSON(f.NewPolicy)
		if err != nil {
			return "", fmt.Errorf("new_policy: %v", err)
		}
		if pd != target {
			return "", errors.New("target is not the digest of new_policy")
		}
	case vaultbinding.BindDeleteAfter:
		if f.TTLSeconds < 0 || f.TTLSeconds > vaultbinding.DeleteAfterMaxTTLSeconds {
			return "", errors.New("ttl_seconds out of range for delete_after")
		}
		if f.SuccessorHandle != "" {
			// A created successor: the old key goes once that key exists.
			if f.SuccessorHandle == f.Handle || len(f.SuccessorHandle) > vaultBatchMaxHandleBytes {
				return "", errors.New("successor_handle must name another key")
			}
			want, err := vaultbinding.DeleteAfterTarget(f.SuccessorHandle, "")
			if err != nil {
				return "", err
			}
			if target != "" && target != want {
				return "", errors.New("target is not the delete_after target of successor_handle")
			}
			return want, nil
		}
		// A promoted successor: only beside that promote, in a batch.
		if !inBatch {
			return "", errors.New("delete_after needs successor_handle, or its successor's promote in a batch")
		}
		if !vaultHex64.MatchString(target) {
			return "", errors.New("target (64 lowercase hex) required for delete_after")
		}
	default:
		return "", errors.New("unknown operation")
	}
	return target, nil
}

// checkVaultMemberIdentities checks the relayed vault identities agree with
// themselves and cover exactly the members named. It authenticates nothing:
// the wallet verifies each quote. It only keeps a caller from naming members
// it has shown no identity for.
func checkVaultMemberIdentities(members []string, ids []vaultbinding.VaultIdentity) error {
	if len(ids) == 0 {
		return errors.New("member_identities required")
	}
	have := map[string]bool{}
	for _, id := range ids {
		if err := id.CheckConsistent(); err != nil {
			return err
		}
		have[id.MemberID] = true
	}
	for _, m := range members {
		if !have[m] {
			return fmt.Errorf("no identity for member %s", m)
		}
	}
	return nil
}

// bindVaultV2 builds the binding for one checked operation and returns it
// with its digest (the WebAuthn challenge) and vault_op.
func bindVaultV2(sub string, f vaultV2Fields, target, nonce string, exp int64) (vaultBindingFields, [32]byte, string, error) {
	b := vaultbinding.BindingV2{
		Members:       f.Members,
		Op:            vaultbinding.BindingOp(f.Operation),
		Handle:        f.Handle,
		Target:        target,
		PolicyVersion: f.PolicyVersion,
		Approver:      vaultbinding.OidcApprover(f.IssuerIndex, sub),
		Nonce:         nonce,
		Exp:           exp,
	}
	text, err := b.Text()
	if err != nil {
		return vaultBindingFields{}, [32]byte{}, "", err
	}
	sum := sha256.Sum256([]byte(text))
	members := append([]string(nil), f.Members...)
	sort.Strings(members)
	fields := vaultBindingFields{
		Members:       members,
		Op:            f.Operation,
		Handle:        f.Handle,
		Target:        dashIfEmpty(target),
		PolicyVersion: f.PolicyVersion,
		Approver:      b.Approver,
		HolderHead:    "-",
		Nonce:         nonce,
		Exp:           exp,
	}
	return fields, sum, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
