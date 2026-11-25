// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build cgo

package store

import (
	"path/filepath"
	"sort"
	"testing"
)

// A device's choice about the number on its icon, and what the count reads.
func TestPushBadgeSetting(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	for _, u := range []string{"alice-a", "alice-b"} {
		if err := db.EnsureUser(u); err != nil {
			t.Fatalf("user: %v", err)
		}
	}
	// One phone under two identities, and a tablet under one.
	for _, r := range [][3]string{{"alice-a", "tag-phone", "phone"}, {"alice-b", "tag-phone", "phone"}, {"alice-a", "tag-tablet", "tablet"}} {
		if err := db.UpsertDevicePushTarget(r[0], r[1], r[2], ""); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	sorted := func(s []string) []string { sort.Strings(s); return s }
	if got := sorted(db.PushTokenUsers("phone")); len(got) != 2 || got[0] != "alice-a" || got[1] != "alice-b" {
		t.Fatalf("identities of the phone = %v", got)
	}
	// On unless the device says otherwise.
	if got := sorted(db.BadgeTokens("alice-a")); len(got) != 2 {
		t.Fatalf("default = %v", got)
	}
	// The choice is the device's: off for every identity it holds.
	if err := db.SetPushBadge("phone", false); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := db.BadgeTokens("alice-a"); len(got) != 1 || got[0] != "tablet" {
		t.Fatalf("alice-a after the phone turned it off = %v", got)
	}
	if got := db.BadgeTokens("alice-b"); len(got) != 0 {
		t.Fatalf("alice-b after the phone turned it off = %v", got)
	}
	if err := db.SetPushBadge("phone", true); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := db.BadgeTokens("alice-b"); len(got) != 1 {
		t.Fatalf("back on = %v", got)
	}
}
