// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package push

import (
	"context"
	"testing"
	"time"
)

type fakeBadgeStore struct {
	users  map[string][]string // token -> identities
	tokens map[string][]string // identity -> badge-taking tokens
}

func (f fakeBadgeStore) PushTokenUsers(t string) []string { return f.users[t] }
func (f fakeBadgeStore) BadgeTokens(u string) []string    { return f.tokens[u] }

type sent struct {
	token string
	n     int
}

func newTestBadges(st fakeBadgeStore, now *time.Time) (*Badges, *[]sent) {
	var out []sent
	b := &Badges{
		open:  map[string]map[string]time.Time{},
		dirty: map[string]bool{},
		last:  map[string]int{},
		db:    st,
		send: func(_ context.Context, token string, n int) error {
			out = append(out, sent{token, n})
			return nil
		},
		now: func() time.Time { return *now },
	}
	return b, &out
}

// One phone, two identities: the icon has one number, the sum of both.
func TestBadgeCountsADevice(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	st := fakeBadgeStore{
		users:  map[string][]string{"phone": {"alice-a", "alice-b"}, "tablet": {"alice-a"}},
		tokens: map[string][]string{"alice-a": {"phone", "tablet"}, "alice-b": {"phone"}},
	}
	b, out := newTestBadges(st, &now)
	b.Open("alice-a", "vault-approval:1", now.Add(5*time.Minute))
	b.Open("alice-a", "vault-approval:2", now.Add(5*time.Minute))
	b.Open("alice-b", "attribute-approval:9", now.Add(time.Minute))
	if got := b.CountFor("phone"); got != 3 {
		t.Fatalf("phone = %d, want 3", got)
	}
	if got := b.CountFor("tablet"); got != 2 {
		t.Fatalf("tablet = %d, want 2", got)
	}
	// Opening the same request again counts it once.
	b.Open("alice-a", "vault-approval:1", now.Add(5*time.Minute))
	if got := b.CountFor("phone"); got != 3 {
		t.Fatalf("phone after a repeat = %d", got)
	}
	// Nothing is sent for an opening: its own push carries the number.
	b.Tick(context.Background())
	if len(*out) != 0 {
		t.Fatalf("sent on open: %v", *out)
	}
}

// An answer sends each of the identity's devices its new number, once.
func TestBadgeFallsWhenAnswered(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	st := fakeBadgeStore{
		users:  map[string][]string{"phone": {"alice"}, "tablet": {"alice"}},
		tokens: map[string][]string{"alice": {"phone", "tablet"}},
	}
	b, out := newTestBadges(st, &now)
	b.Open("alice", "r1", now.Add(time.Minute))
	b.Open("alice", "r2", now.Add(time.Minute))
	b.Close("alice", "r1")
	b.Close("alice", "r2")
	b.Close("alice", "r2") // already closed: nothing more to say
	b.Tick(context.Background())
	if len(*out) != 2 {
		t.Fatalf("two answers in one moment are one correction per device, got %v", *out)
	}
	for _, s := range *out {
		if s.n != 0 {
			t.Fatalf("%s = %d, want 0", s.token, s.n)
		}
	}
	// Closing what was never open sends nothing.
	*out = nil
	b.Close("alice", "never")
	b.Tick(context.Background())
	if len(*out) != 0 {
		t.Fatalf("sent for nothing: %v", *out)
	}
}

// A request that lapses leaves the count by itself.
func TestBadgeFallsWhenARequestLapses(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	st := fakeBadgeStore{users: map[string][]string{"phone": {"alice"}}, tokens: map[string][]string{"alice": {"phone"}}}
	b, out := newTestBadges(st, &now)
	b.Open("alice", "short", now.Add(time.Minute))
	b.Open("alice", "long", now.Add(time.Hour))
	now = now.Add(2 * time.Minute)
	if got := b.CountFor("phone"); got != 1 {
		t.Fatalf("after the short one lapsed = %d", got)
	}
	b.Tick(context.Background())
	if len(*out) != 1 || (*out)[0] != (sent{"phone", 1}) {
		t.Fatalf("correction = %v", *out)
	}
	// And only once.
	*out = nil
	b.Tick(context.Background())
	if len(*out) != 0 {
		t.Fatalf("sent again: %v", *out)
	}
}

// A device that asked for no badge gets none, and the number is capped.
func TestBadgeRespectsTheDeviceAndTheCap(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	st := fakeBadgeStore{
		users:  map[string][]string{"quiet": {"bob"}, "loud": {"bob"}},
		tokens: map[string][]string{"bob": {"loud"}}, // "quiet" turned it off
	}
	b, out := newTestBadges(st, &now)
	if b.Takes("bob", "quiet") || !b.Takes("bob", "loud") {
		t.Fatal("takes")
	}
	for i := 0; i < 150; i++ {
		b.Open("bob", "r"+time.Duration(i).String(), now.Add(time.Hour))
	}
	if got := b.CountFor("loud"); got != maxBadge {
		t.Fatalf("cap = %d", got)
	}
	b.Close("bob", "r0s")
	b.Tick(context.Background())
	for _, s := range *out {
		if s.token == "quiet" {
			t.Fatalf("a device that asked for no badge was sent one: %v", *out)
		}
	}
	// No counter at all: nothing breaks.
	var none *Badges
	none.Open("x", "y", now)
	none.Close("x", "y")
	none.Tick(context.Background())
	if none.CountFor("t") != 0 || none.Takes("x", "t") {
		t.Fatal("nil counter")
	}
}

// What privasys.id keeps for the wallet to list is counted from where it is
// kept, and leaves the number however it ends, without anyone saying so.
func TestBadgeCountsKeptRequests(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	st := fakeBadgeStore{
		users:  map[string][]string{"phone": {"alice-a", "alice-b"}},
		tokens: map[string][]string{"alice-a": {"phone"}, "alice-b": {"phone"}},
	}
	b, out := newTestBadges(st, &now)
	kept := map[string]int{"alice-a": 2, "alice-b": 1}
	b.AddSource(func(u string) int { return kept[u] })
	b.Open("alice-a", "vault-approval:1", now.Add(5*time.Minute))
	if got := b.CountFor("phone"); got != 4 {
		t.Fatalf("phone = %d, want 4", got)
	}
	// The push that announced the last of them carried the number.
	b.sent("phone", 4)
	b.Tick(context.Background())
	if len(*out) != 0 {
		t.Fatalf("a device already showing its number was sent %v", *out)
	}
	// One is answered in the app; nothing tells the counter.
	kept["alice-a"] = 1
	now = now.Add(recheckEvery)
	b.Tick(context.Background())
	if len(*out) != 1 || (*out)[0] != (sent{"phone", 3}) {
		t.Fatalf("after one was answered: %v", *out)
	}
	// Unchanged: nothing more is sent, however often it is counted.
	now = now.Add(recheckEvery)
	b.Tick(context.Background())
	if len(*out) != 1 {
		t.Fatalf("an unchanged number was sent again: %v", *out)
	}
	// All gone: the icon is cleared once, and the device is not counted again.
	kept["alice-a"], kept["alice-b"] = 0, 0
	b.Close("alice-a", "vault-approval:1")
	b.Tick(context.Background())
	if len(*out) != 2 || (*out)[1] != (sent{"phone", 0}) {
		t.Fatalf("after all were answered: %v", *out)
	}
	now = now.Add(recheckEvery)
	b.Tick(context.Background())
	if len(*out) != 2 {
		t.Fatalf("a cleared device was sent again: %v", *out)
	}
}
