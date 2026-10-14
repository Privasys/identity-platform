// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package apps serves the holder's standing relationship with one app: the
// wallet's "remove this app", which ends everything the IdP keeps for the
// pair and, with it, the app's only way back to the person.
package apps

import (
	"errors"
	"log"
	"net/http"

	"github.com/Privasys/idp/internal/capasks"
	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/sessions"
	"github.com/Privasys/idp/internal/spend"
)

// Authenticate resolves the caller (wallet session or bearer) or writes the
// error and returns "".
type Authenticate func(w http.ResponseWriter, r *http.Request) string

// Remover ends a holder's relationship with an app.
type Remover struct {
	Sessions *sessions.Store
	Spend    *spend.Store
	Asks     *capasks.Store
	Clients  *clients.Registry
	// OnConsentRevoked tells the platform the consent's ledger handle is dead.
	OnConsentRevoked func(c *spend.Consent)
}

// Remove ends everything for (userID, appID): the relationship row and the
// sessions of the client that stands for the app (browsers end as
// signed-out), the spend consent (its handle is reported dead), and the asks
// the app had waiting. Returns the client id, or "" when no client stands
// for the app (the consent and asks still go).
func (rm *Remover) Remove(userID, appID string) (clientID string, sessionsEnded int, err error) {
	appID = clients.NormaliseAppID(appID)
	if rm.Clients != nil {
		clientID = rm.Clients.ClientOfApp(appID)
	}
	if clientID != "" && rm.Sessions != nil {
		n, rerr := rm.Sessions.RemoveHolder(userID, clientID)
		if rerr != nil {
			return clientID, n, rerr
		}
		sessionsEnded = n
	}
	if rm.Spend != nil {
		c, gerr := rm.Spend.Get(userID, appID)
		switch {
		case gerr == nil:
			if rerr := rm.Spend.Revoke(userID, appID); rerr != nil && !errors.Is(rerr, spend.ErrNotFound) {
				return clientID, sessionsEnded, rerr
			}
			if rm.OnConsentRevoked != nil {
				rm.OnConsentRevoked(c)
			}
		case errors.Is(gerr, spend.ErrNotFound):
		default:
			return clientID, sessionsEnded, gerr
		}
	}
	if rm.Asks != nil {
		rm.Asks.RemoveByApp(userID, appID)
	}
	return clientID, sessionsEnded, nil
}

// HandleRemove serves DELETE /wallet/apps/{app_id}. 204 whether or not
// anything was there: removing an app the holder never used is not an error.
func HandleRemove(rm *Remover, auth Authenticate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth(w, r)
		if userID == "" {
			return
		}
		appID := clients.NormaliseAppID(r.PathValue("app_id"))
		if appID == "" {
			http.Error(w, `{"error":"app_id must be an attested app id"}`, http.StatusBadRequest)
			return
		}
		clientID, ended, err := rm.Remove(userID, appID)
		if err != nil {
			log.Printf("[apps] remove %s… for %s…: %v", appID[:8], userID[:min(8, len(userID))], err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		log.Printf("[apps] %s… removed app %s… (client %q, %d session(s) ended)", userID[:min(8, len(userID))], appID[:8], clientID, ended)
		w.WriteHeader(http.StatusNoContent)
	}
}
