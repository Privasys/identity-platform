// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package clients manages OIDC client registrations.
package clients

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Privasys/idp/internal/store"
)

// Client represents a registered OIDC client.
type Client struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// ValidRedirectURI checks if the given URI is in the client's registered redirect URIs.
func (c *Client) ValidRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// Registry manages OIDC client registrations backed by SQLite.
type Registry struct {
	db *store.DB
}

// NewRegistry creates a new client registry.
func NewRegistry(db *store.DB) *Registry {
	return &Registry{db: db}
}

// Get retrieves a client by ID.
func (reg *Registry) Get(clientID string) (*Client, error) {
	var name, redirectURIsJSON string
	err := reg.db.QueryRow(
		"SELECT client_name, redirect_uris FROM clients WHERE client_id = ?",
		clientID,
	).Scan(&name, &redirectURIsJSON)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	var uris []string
	json.Unmarshal([]byte(redirectURIsJSON), &uris)

	return &Client{
		ClientID:     clientID,
		ClientName:   name,
		RedirectURIs: uris,
	}, nil
}

// Register creates a new OIDC client.
func (reg *Registry) Register(name string, redirectURIs []string) (*Client, error) {
	b := make([]byte, 16)
	rand.Read(b)
	clientID := hex.EncodeToString(b)

	urisJSON, _ := json.Marshal(redirectURIs)

	_, err := reg.db.Exec(
		"INSERT INTO clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)",
		clientID, name, string(urisJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("register client: %w", err)
	}

	return &Client{
		ClientID:     clientID,
		ClientName:   name,
		RedirectURIs: redirectURIs,
	}, nil
}

// RegisterWithID creates a client with a specific client_id (for pre-known clients like Zitadel).
func (reg *Registry) RegisterWithID(clientID, name string, redirectURIs []string) (*Client, error) {
	urisJSON, _ := json.Marshal(redirectURIs)

	_, err := reg.db.Exec(
		`INSERT INTO clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)
		 ON CONFLICT(client_id) DO UPDATE SET client_name = excluded.client_name, redirect_uris = excluded.redirect_uris`,
		clientID, name, string(urisJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("register client: %w", err)
	}

	return &Client{
		ClientID:     clientID,
		ClientName:   name,
		RedirectURIs: redirectURIs,
	}, nil
}

// HandleRegister is the HTTP handler for POST /clients.
func HandleRegister(reg *Registry, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Admin auth.
		if adminToken != "" {
			auth := r.Header.Get("Authorization")
			if len(auth) < 8 || auth[7:] != adminToken {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}

		var req struct {
			ClientID     string   `json:"client_id,omitempty"`
			ClientName   string   `json:"client_name"`
			RedirectURIs []string `json:"redirect_uris"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}

		if req.ClientName == "" || len(req.RedirectURIs) == 0 {
			http.Error(w, `{"error":"client_name and redirect_uris required"}`, http.StatusBadRequest)
			return
		}

		var client *Client
		var err error
		if req.ClientID != "" {
			client, err = reg.RegisterWithID(req.ClientID, req.ClientName, req.RedirectURIs)
		} else {
			client, err = reg.Register(req.ClientName, req.RedirectURIs)
		}
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(client)
	}
}
