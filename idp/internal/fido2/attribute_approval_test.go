// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

import (
	"testing"
	"time"
)

func TestAttributeApprovalBindingCommitsToTheExactSet(t *testing.T) {
	base := computeAttributeApprovalBinding("sess-1", "client-1", []string{"email", "birthdate"}, 100)

	// Key order must not matter — the binding sorts.
	if computeAttributeApprovalBinding("sess-1", "client-1", []string{"birthdate", "email"}, 100) != base {
		t.Fatal("binding depends on key order")
	}
	// Any widening of the set is a different approval.
	if computeAttributeApprovalBinding("sess-1", "client-1", []string{"email", "birthdate", "passport_number_id"}, 100) == base {
		t.Fatal("a wider set produced the same binding")
	}
	// A different session, client, or expiry is a different approval.
	if computeAttributeApprovalBinding("sess-2", "client-1", []string{"email", "birthdate"}, 100) == base {
		t.Fatal("a different session produced the same binding")
	}
	if computeAttributeApprovalBinding("sess-1", "client-2", []string{"email", "birthdate"}, 100) == base {
		t.Fatal("a different client produced the same binding")
	}
	if computeAttributeApprovalBinding("sess-1", "client-1", []string{"email", "birthdate"}, 101) == base {
		t.Fatal("a different expiry produced the same binding")
	}
	// The encoding must be injective: one comma-bearing key must never
	// collide with the two keys it would render as under a plain join.
	if computeAttributeApprovalBinding("sess-1", "client-1", []string{"birthdate,email"}, 100) == base {
		t.Fatal("a comma-bearing key collides with the joined set")
	}
}

func TestAttrPendingStoreIsSingleUse(t *testing.T) {
	s := &attrPendingStore{pending: map[string]*attrPendingEntry{}}
	s.put("cap-1", &attrPendingEntry{sub: "u1", expiresAt: time.Now().Add(time.Minute)})

	if _, ok := s.get("cap-1"); !ok {
		t.Fatal("get before completion failed")
	}
	if _, ok := s.pop("cap-1"); !ok {
		t.Fatal("first pop failed")
	}
	// A replayed completion finds nothing.
	if _, ok := s.pop("cap-1"); ok {
		t.Fatal("second pop succeeded — approvals must be single-use")
	}

	// Expired entries are dead even before cleanup runs.
	s.put("cap-2", &attrPendingEntry{sub: "u1", expiresAt: time.Now().Add(-time.Second)})
	if _, ok := s.get("cap-2"); ok {
		t.Fatal("expired entry still readable")
	}
	if _, ok := s.pop("cap-2"); ok {
		t.Fatal("expired entry still consumable")
	}
}
