// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package spend

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/idp/internal/store"
)

// The ledger outbox.
//
// A spend consent binds a holder's credits to a per-consent handle. The
// platform's billing layer debits by that handle and must be told, once,
// which account it stands for: that statement (internal/tokens
// LedgerHandleStatement) is the only place the account behind a spend
// token is named, and it travels from here, signed, to every control plane
// the IdP serves. Written in the same transaction as the consent and
// delivered with retry, so an outage of the control plane never blocks a
// consent and never loses the binding; a spend before delivery lands is a
// retryable "consent pending" at the callee, never a debit of a guessed
// account.

// OutboxTarget is one control plane to tell.
type OutboxTarget struct {
	URL   string
	Token string
}

// Outbox persists statements and delivers them.
type Outbox struct {
	db      *store.DB
	targets []OutboxTarget
	http    *http.Client
	now     func() time.Time
	wake    chan struct{}
}

// NewOutbox creates the table if needed. Targets without a URL or token are
// skipped (a dev deployment with no second control plane).
func NewOutbox(db *store.DB, targets []OutboxTarget, client *http.Client) (*Outbox, error) {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ledger_outbox (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			handle       TEXT NOT NULL,
			kind         TEXT NOT NULL,
			statement    TEXT NOT NULL,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			attempts     INTEGER NOT NULL DEFAULT 0,
			next_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			delivered_at DATETIME
		);
		CREATE INDEX IF NOT EXISTS idx_ledger_outbox_pending ON ledger_outbox(delivered_at, next_at);
	`); err != nil {
		return nil, fmt.Errorf("create ledger_outbox: %w", err)
	}
	var live []OutboxTarget
	for _, t := range targets {
		if t.URL != "" && t.Token != "" {
			live = append(live, OutboxTarget{URL: strings.TrimRight(t.URL, "/"), Token: t.Token})
		}
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Outbox{db: db, targets: live, http: client, now: time.Now, wake: make(chan struct{}, 1)}, nil
}

// Enqueue stores a signed statement for delivery and nudges the deliverer.
func (o *Outbox) Enqueue(handle, kind, statement string) error {
	if o == nil {
		return nil
	}
	now := o.now().UTC()
	if _, err := o.db.Exec(
		`INSERT INTO ledger_outbox (handle, kind, statement, created_at, next_at) VALUES (?, ?, ?, ?, ?)`,
		handle, kind, statement, now, now); err != nil {
		return err
	}
	select {
	case o.wake <- struct{}{}:
	default:
	}
	return nil
}

// Run delivers until ctx ends: on each nudge and every interval.
func (o *Outbox) Run(ctx context.Context, every time.Duration) {
	if o == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		o.DeliverPending(ctx)
		select {
		case <-ctx.Done():
			return
		case <-o.wake:
		case <-t.C:
		}
	}
}

// DeliverPending tries every due statement once, oldest first. Returns how
// many were delivered.
func (o *Outbox) DeliverPending(ctx context.Context) int {
	now := o.now().UTC()
	rows, err := o.db.Query(
		`SELECT id, handle, kind, statement, attempts FROM ledger_outbox
		  WHERE delivered_at IS NULL AND next_at <= ? ORDER BY id LIMIT 50`, now)
	if err != nil {
		log.Printf("spend/outbox: list: %v", err)
		return 0
	}
	type item struct {
		id       int64
		handle   string
		kind     string
		stmt     string
		attempts int
	}
	var due []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.handle, &it.kind, &it.stmt, &it.attempts); err != nil {
			rows.Close()
			log.Printf("spend/outbox: scan: %v", err)
			return 0
		}
		due = append(due, it)
	}
	rows.Close()
	delivered := 0
	for _, it := range due {
		if ctx.Err() != nil {
			return delivered
		}
		if err := o.deliver(ctx, it.stmt); err != nil {
			wait := time.Duration(1<<uint(min(it.attempts, 9))) * 5 * time.Second
			if wait > time.Hour {
				wait = time.Hour
			}
			_, _ = o.db.Exec(`UPDATE ledger_outbox SET attempts = attempts + 1, next_at = ? WHERE id = ?`,
				o.now().UTC().Add(wait), it.id)
			log.Printf("spend/outbox: %s %s… attempt %d failed, next in %s: %v", it.kind, it.handle[:min(8, len(it.handle))], it.attempts+1, wait, err)
			continue
		}
		_, _ = o.db.Exec(`UPDATE ledger_outbox SET delivered_at = ?, attempts = attempts + 1 WHERE id = ?`, o.now().UTC(), it.id)
		delivered++
	}
	return delivered
}

// deliver posts one statement to every target. A target that does not know
// the app answers 404 and is done; anything else but 2xx is retried.
func (o *Outbox) deliver(ctx context.Context, statement string) error {
	if len(o.targets) == 0 {
		return fmt.Errorf("no control plane configured")
	}
	body, _ := json.Marshal(map[string]string{"statement": statement})
	for _, t := range o.targets {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL+"/api/v1/internal/ledger-handles", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+t.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := o.http.Do(req)
		if err != nil {
			return fmt.Errorf("%s: %w", t.URL, err)
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("%s: status %d", t.URL, resp.StatusCode)
		}
	}
	return nil
}

// Pending reports how many statements await delivery (tests, metrics).
func (o *Outbox) Pending() int {
	var n int
	if err := o.db.QueryRow(`SELECT COUNT(*) FROM ledger_outbox WHERE delivered_at IS NULL`).Scan(&n); err != nil && err != sql.ErrNoRows {
		return -1
	}
	return n
}
