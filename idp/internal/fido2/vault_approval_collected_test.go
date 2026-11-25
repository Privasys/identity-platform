// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package fido2

import (
	"testing"
	"time"
)

// A token is handed out once. The one it was handed to is told so if it asks
// again; nobody else learns anything, and a decline or an expiry is not a
// collection.
func TestCollectedTokenIsToldToItsCollectorOnly(t *testing.T) {
	s := newVaultResultStore()
	exp := time.Now().Add(time.Minute)

	s.put("op", "owner", "token", exp.Unix())
	if s.collected("op", "owner") {
		t.Fatal("collected before anyone took it")
	}
	if _, ok := s.take("op", "someone-else"); ok {
		t.Fatal("another subject took the token")
	}
	if s.collected("op", "someone-else") || s.collected("op", "owner") {
		t.Fatal("a refused take counted as a collection")
	}
	if e, ok := s.take("op", "owner"); !ok || e.token != "token" {
		t.Fatal("the owner could not take the token")
	}
	if _, ok := s.take("op", "owner"); ok {
		t.Fatal("the token was handed out twice")
	}
	if !s.collected("op", "owner") {
		t.Fatal("the collector is not told it already has the token")
	}
	if s.collected("op", "someone-else") || s.collected("op", "") {
		t.Fatal("someone else learns the token was collected")
	}
	if s.outcome("op") != "approved" {
		t.Fatal("collection changed how the approval reads")
	}

	// A decline is taken once too, but it is not a token that went missing.
	s.decline("no", "owner", exp)
	if _, ok := s.take("no", "owner"); !ok {
		t.Fatal("the decline was not delivered")
	}
	if s.collected("no", "owner") {
		t.Fatal("a delivered decline reads as a collected token")
	}

	// Past its expiry, nothing is said.
	s.put("old", "owner", "token", time.Now().Add(time.Hour).Unix())
	s.take("old", "owner")
	o := s.outcomes["old"]
	o.expiresAt = time.Now().Add(-time.Second)
	s.outcomes["old"] = o
	if s.collected("old", "owner") {
		t.Fatal("an expired approval still reads as collected")
	}
}
