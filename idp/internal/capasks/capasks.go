// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package capasks remembers the access requests the IdP has relayed to a
// holder's wallet, for as long as the asking app keeps them open.
//
// An app asks for a capability by having the IdP push the holder's wallet a
// nonce and the host to fetch it from. The push was the only way the wallet
// ever learned of the ask, and a push is best effort: swiped away, never
// delivered, or arriving while the phone was off, the ask sat unanswerable
// until it expired and the app had to ask again. This list is what lets the
// wallet find one without the push.
//
// It holds exactly what the push carried (nonce, host, app id and name) and
// nothing the push did not. The wallet still learns everything that matters
// inside the attested channel to that host, and a nonce the app has already
// settled or dropped is refused there, so a stale entry here costs one
// failed fetch, never a wrong approval.
package capasks

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// TTL matches how long the enclave OS keeps an ask open. Longer would list
// asks the app can no longer honour; shorter would drop ones it still can.
const TTL = 15 * time.Minute

// maxPerHolder bounds what one holder's list can grow to, so an app that asks
// in a loop cannot turn this into unbounded memory.
const maxPerHolder = 32

// Ask is one relayed request, as the wallet sees it.
type Ask struct {
	Nonce     string `json:"nonce"`
	AppHost   string `json:"app_host"`
	AppID     string `json:"app_id,omitempty"`
	AppName   string `json:"app_name,omitempty"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// Store is the in-memory list, keyed by holder then nonce. In memory on
// purpose: an ask lives for minutes, and losing the list on a restart loses
// nothing a new ask would not restore.
type Store struct {
	mu   sync.Mutex
	asks map[string]map[string]Ask
	now  func() time.Time
}

// New returns an empty store that sweeps expired asks once a minute.
func New() *Store {
	s := newStore(time.Now)
	go func() {
		for {
			time.Sleep(time.Minute)
			s.sweep()
		}
	}()
	return s
}

func newStore(now func() time.Time) *Store {
	return &Store{asks: make(map[string]map[string]Ask), now: now}
}

// Put records an ask relayed to sub. A repeated nonce replaces the old entry.
func (s *Store) Put(sub, nonce, appHost, appID, appName string) {
	if sub == "" || nonce == "" || appHost == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	mine := s.asks[sub]
	if mine == nil {
		mine = make(map[string]Ask)
		s.asks[sub] = mine
	}
	mine[nonce] = Ask{
		Nonce:     nonce,
		AppHost:   appHost,
		AppID:     appID,
		AppName:   appName,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(TTL).Unix(),
	}
	// Over the bound, the oldest go first: the newest ask is the one the
	// holder is most likely waiting on.
	for len(mine) > maxPerHolder {
		oldest := ""
		for n, a := range mine {
			if oldest == "" || a.CreatedAt < mine[oldest].CreatedAt {
				oldest = n
			}
		}
		delete(mine, oldest)
	}
}

// ListFor returns sub's live asks, newest first.
func (s *Store) ListFor(sub string) []Ask {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	out := make([]Ask, 0, len(s.asks[sub]))
	for _, a := range s.asks[sub] {
		if a.ExpiresAt > now {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// Remove drops one of sub's asks. Another holder's nonce is never touched.
func (s *Store) Remove(sub, nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mine := s.asks[sub]; mine != nil {
		delete(mine, nonce)
		if len(mine) == 0 {
			delete(s.asks, sub)
		}
	}
}

func (s *Store) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	for sub, mine := range s.asks {
		for n, a := range mine {
			if a.ExpiresAt <= now {
				delete(mine, n)
			}
		}
		if len(mine) == 0 {
			delete(s.asks, sub)
		}
	}
}

// Authenticate resolves the caller to a user id, or writes the error and
// returns "". The IdP's existing bearer check (wallet session or JWT) fits.
type Authenticate func(w http.ResponseWriter, r *http.Request) string

// HandleList serves GET /capability-requests/pending: the caller's live asks.
func HandleList(s *Store, auth Authenticate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := auth(w, r)
		if sub == "" {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string][]Ask{"pending": s.ListFor(sub)})
	}
}

// HandleDismiss serves DELETE /capability-requests/pending/{nonce}, which the
// wallet calls once the holder has decided. Idempotent: 204 whether or not
// the ask was still listed.
func HandleDismiss(s *Store, auth Authenticate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := auth(w, r)
		if sub == "" {
			return
		}
		s.Remove(sub, r.PathValue("nonce"))
		w.WriteHeader(http.StatusNoContent)
	}
}
