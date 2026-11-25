// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package push

import (
	"context"
	"log"
	"sync"
	"time"
)

// The number on the wallet's icon.
//
// A wallet shows how many things wait on its holder. While it runs it counts
// them itself. When it is closed nothing on the phone can, so the number is
// sent with the push that announces a request, and again, alone, when a
// request is answered or lapses.
//
// What travels is one integer per device and nothing else: the push that
// corrects a count carries no data, no title and no type. A count is still
// about a person, so it is never logged, never written to disk, and a device
// that asks for no badge gets none.
//
// Two kinds of thing are counted. A request that lives only as long as its
// push (a vault approval, a request for more data) is opened here and closed
// when answered. What an app sent and privasys.id keeps for the wallet to list
// (a request, an approval, a form, a capability ask) is counted from where it
// is kept (AddSource), so it leaves the number however it ends.
//
// The count is per DEVICE. A phone holds several identities under one push
// token, and its icon has one number. The sum is taken from the existing push
// registrations at the moment it is needed; nothing here records which
// identities share a token.

// maxBadge is the most the icon shows; beyond it the number says nothing more.
const maxBadge = 99

// BadgeStore is what the count reads from the database.
type BadgeStore interface {
	// PushTokenUsers lists the identities a push token is registered for.
	PushTokenUsers(token string) []string
	// BadgeTokens lists an identity's push tokens that take a badge.
	BadgeTokens(userID string) []string
}

// Waiting reports how many kept things wait on an identity.
type Waiting func(userID string) int

// recheckEvery is how often a device showing a number has it counted again:
// what catches a kept request that was answered, dismissed or lapsed.
const recheckEvery = 15 * time.Second

// Badges counts the open requests of each identity, in memory. Lost on a
// restart, as the requests themselves are: the next count may then be low,
// and the wallet corrects it the moment it runs.
type Badges struct {
	mu    sync.Mutex
	open  map[string]map[string]time.Time // identity -> request -> when it lapses
	dirty map[string]bool                 // tokens whose number may have changed
	// last is the number each device was last sent, while it is not zero:
	// which devices to count again, and what makes a correction worth sending.
	last      map[string]int
	rechecked time.Time
	sources   []Waiting
	db        BadgeStore
	send      func(ctx context.Context, token string, n int) error
	now       func() time.Time
}

// NewBadges returns a counter that sends its corrections through s.
func NewBadges(db BadgeStore, s *Sender) *Badges {
	return &Badges{
		open:  map[string]map[string]time.Time{},
		dirty: map[string]bool{},
		last:  map[string]int{},
		db:    db,
		send:  s.badge,
		now:   time.Now,
	}
}

// AddSource adds a place where things waiting on an identity are kept.
func (b *Badges) AddSource(w Waiting) {
	b.mu.Lock()
	b.sources = append(b.sources, w)
	b.mu.Unlock()
}

// sent records the number a device was just told.
func (b *Badges) sent(token string, n int) {
	b.mu.Lock()
	if n > 0 {
		b.last[token] = n
	} else {
		delete(b.last, token)
	}
	b.mu.Unlock()
}

// Open records a request waiting on userID until expires.
func (b *Badges) Open(userID, request string, expires time.Time) {
	if b == nil || userID == "" || request == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open[userID] == nil {
		b.open[userID] = map[string]time.Time{}
	}
	b.open[userID][request] = expires
}

// Close records that a request was answered, and marks the identity's devices
// for a corrected number.
func (b *Badges) Close(userID, request string) {
	if b == nil || userID == "" || request == "" {
		return
	}
	b.mu.Lock()
	_, was := b.open[userID][request]
	delete(b.open[userID], request)
	if len(b.open[userID]) == 0 {
		delete(b.open, userID)
	}
	b.mu.Unlock()
	if was {
		b.touch(userID)
	}
}

// touch marks an identity's badge-taking devices as needing their number sent.
func (b *Badges) touch(userID string) {
	tokens := b.db.BadgeTokens(userID)
	b.mu.Lock()
	for _, t := range tokens {
		b.dirty[t] = true
	}
	b.mu.Unlock()
}

// Takes reports whether a device takes a badge for this identity.
func (b *Badges) Takes(userID, token string) bool {
	if b == nil {
		return false
	}
	for _, t := range b.db.BadgeTokens(userID) {
		if t == token {
			return true
		}
	}
	return false
}

// CountFor is the number for one device: the open requests of every identity
// registered to its token.
func (b *Badges) CountFor(token string) int {
	if b == nil {
		return 0
	}
	users := b.db.PushTokenUsers(token)
	now := b.now()
	b.mu.Lock()
	sources := b.sources
	n := 0
	for _, u := range users {
		for _, exp := range b.open[u] {
			if exp.IsZero() || exp.After(now) {
				n++
			}
		}
	}
	b.mu.Unlock()
	// Outside the lock: a source reads its own store.
	for _, u := range users {
		for _, waiting := range sources {
			n += waiting(u)
		}
	}
	if n > maxBadge {
		n = maxBadge
	}
	return n
}

// Tick drops the requests that have lapsed and sends every device whose
// number may have changed its new one, once. Called on a timer, which is also
// what joins several changes in the same moment into one push.
func (b *Badges) Tick(ctx context.Context) {
	if b == nil {
		return
	}
	now := b.now()
	var lapsed []string
	b.mu.Lock()
	for user, reqs := range b.open {
		gone := false
		for r, exp := range reqs {
			if !exp.IsZero() && !exp.After(now) {
				delete(reqs, r)
				gone = true
			}
		}
		if len(reqs) == 0 {
			delete(b.open, user)
		}
		if gone {
			lapsed = append(lapsed, user)
		}
	}
	b.mu.Unlock()
	for _, u := range lapsed {
		b.touch(u)
	}

	b.mu.Lock()
	// Every so often, each device showing a number is counted again.
	if now.Sub(b.rechecked) >= recheckEvery {
		b.rechecked = now
		for t := range b.last {
			b.dirty[t] = true
		}
	}
	type due struct {
		token string
		was   int
		known bool
	}
	tokens := make([]due, 0, len(b.dirty))
	for t := range b.dirty {
		was, known := b.last[t]
		tokens = append(tokens, due{t, was, known})
	}
	b.dirty = map[string]bool{}
	b.mu.Unlock()

	failed := 0
	for _, d := range tokens {
		n := b.CountFor(d.token)
		// Nothing to say to a device already showing this number.
		if d.known && n == d.was {
			continue
		}
		if err := b.send(ctx, d.token, n); err != nil {
			failed++
			continue
		}
		b.sent(d.token, n)
	}
	if failed > 0 {
		// How many, never whose or what number: a count is about a person.
		log.Printf("[push] badge: %d of %d corrections were refused", failed, len(tokens))
	}
}

// Run ticks until ctx ends.
func (b *Badges) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.Tick(ctx)
		}
	}
}

// badge sends a device its number and nothing else.
func (s *Sender) badge(ctx context.Context, token string, n int) error {
	_, err := s.post(ctx, map[string]any{"to": token, "badge": n, "priority": "normal"})
	return err
}

// The counter every push goes through, when there is one.
var badges *Badges

// SetBadges installs the counter. Without one no push carries a number.
func SetBadges(b *Badges) { badges = b }

// AddWaiting adds a place where things waiting on an identity are kept, when
// there is a counter.
func AddWaiting(w Waiting) {
	if badges != nil {
		badges.AddSource(w)
	}
}

// CloseRequest records that a request was answered or declined.
func CloseRequest(userID, request string) { badges.Close(userID, request) }
