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

	"golang.org/x/crypto/bcrypt"

	"github.com/Privasys/idp/internal/attributes"
	"github.com/Privasys/idp/internal/store"
)

// Client represents a registered OIDC client.
type Client struct {
	ClientID           string   `json:"client_id"`
	ClientName         string   `json:"client_name"`
	ClientSecret       string   `json:"client_secret,omitempty"` // only returned on registration
	RedirectURIs       []string `json:"redirect_uris"`
	Confidential       bool     `json:"confidential"`                  // true if client has a secret
	RequiredAttributes []string `json:"required_attributes,omitempty"` // per-app attribute whitelist; empty = all scope-derived
	// Billable relying party: this client is the paying consumer of attributes.
	// At voucher mint, BillingAccountID (a management-service account UUID) is
	// charged and RPID is stamped into the voucher + disclosure audience.
	BillableRP       bool   `json:"billable_rp,omitempty"`
	BillingAccountID string `json:"billing_account_id,omitempty"`
	RPID             string `json:"rp_id,omitempty"`
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
	var name, secretHash, redirectURIsJSON, requiredAttrsJSON, billingAccountID, rpID string
	var billableRP int
	err := reg.db.QueryRow(
		"SELECT client_name, client_secret, redirect_uris, required_attributes, billable_rp, billing_account_id, rp_id FROM clients WHERE client_id = ?",
		clientID,
	).Scan(&name, &secretHash, &redirectURIsJSON, &requiredAttrsJSON, &billableRP, &billingAccountID, &rpID)
	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	var uris []string
	json.Unmarshal([]byte(redirectURIsJSON), &uris)

	var requiredAttrs []string
	json.Unmarshal([]byte(requiredAttrsJSON), &requiredAttrs)

	return &Client{
		ClientID:           clientID,
		ClientName:         name,
		RedirectURIs:       uris,
		Confidential:       secretHash != "",
		RequiredAttributes: requiredAttrs,
		BillableRP:         billableRP != 0,
		BillingAccountID:   billingAccountID,
		RPID:               rpID,
	}, nil
}

// SetBilling marks a client as a billable relying party and links the
// management-service billing account + RP id (used by the voucher-mint path).
// rpID defaults to the client_id when empty. Returns the updated client.
func (reg *Registry) SetBilling(clientID string, billable bool, billingAccountID, rpID string) (*Client, error) {
	if rpID == "" {
		rpID = clientID
	}
	b := 0
	if billable {
		b = 1
	}
	res, err := reg.db.Exec(
		"UPDATE clients SET billable_rp = ?, billing_account_id = ?, rp_id = ? WHERE client_id = ?",
		b, billingAccountID, rpID, clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("set billing: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("client not found")
	}
	return reg.Get(clientID)
}

// validateRequiredAttributes rejects any attribute key that is not in the
// canonical referential (shared/canonical-attributes.json). An empty/nil list
// is allowed and means "all scope-derived attributes". This guarantees a client
// can only ever request attributes that exist in the golden referential —
// requesting anything outside it is refused at registration, not silently
// dropped at /authorize.
func validateRequiredAttributes(requiredAttributes []string) error {
	for _, a := range requiredAttributes {
		if !attributes.Keys[a] {
			return fmt.Errorf("unknown required attribute %q: not in the canonical referential", a)
		}
	}
	return nil
}

// Register creates a new OIDC client.
func (reg *Registry) Register(name string, redirectURIs []string, secret string, requiredAttributes []string) (*Client, error) {
	if err := validateRequiredAttributes(requiredAttributes); err != nil {
		return nil, err
	}

	b := make([]byte, 16)
	rand.Read(b)
	clientID := hex.EncodeToString(b)

	var secretHash string
	if secret != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hash secret: %w", err)
		}
		secretHash = string(h)
	}

	urisJSON, _ := json.Marshal(redirectURIs)
	attrsJSON, _ := json.Marshal(requiredAttributes)

	_, err := reg.db.Exec(
		"INSERT INTO clients (client_id, client_name, client_secret, redirect_uris, required_attributes) VALUES (?, ?, ?, ?, ?)",
		clientID, name, secretHash, string(urisJSON), string(attrsJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("register client: %w", err)
	}

	return &Client{
		ClientID:           clientID,
		ClientName:         name,
		ClientSecret:       secret, // return plaintext only on creation
		RedirectURIs:       redirectURIs,
		Confidential:       secret != "",
		RequiredAttributes: requiredAttributes,
	}, nil
}

// RegisterWithID creates a client with a specific client_id (for pre-known clients).
func (reg *Registry) RegisterWithID(clientID, name string, redirectURIs []string, secret string, requiredAttributes []string) (*Client, error) {
	if err := validateRequiredAttributes(requiredAttributes); err != nil {
		return nil, err
	}

	var secretHash string
	if secret != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hash secret: %w", err)
		}
		secretHash = string(h)
	}

	urisJSON, _ := json.Marshal(redirectURIs)
	attrsJSON, _ := json.Marshal(requiredAttributes)

	_, err := reg.db.Exec(
		`INSERT INTO clients (client_id, client_name, client_secret, redirect_uris, required_attributes) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(client_id) DO UPDATE SET client_name = excluded.client_name, client_secret = excluded.client_secret, redirect_uris = excluded.redirect_uris, required_attributes = excluded.required_attributes`,
		clientID, name, secretHash, string(urisJSON), string(attrsJSON),
	)
	if err != nil {
		return nil, fmt.Errorf("register client: %w", err)
	}

	return &Client{
		ClientID:           clientID,
		ClientName:         name,
		ClientSecret:       secret,
		RedirectURIs:       redirectURIs,
		Confidential:       secret != "",
		RequiredAttributes: requiredAttributes,
	}, nil
}

// VerifySecret checks whether the provided secret matches the client's stored hash.
// Returns true for public clients (no secret set) when secret is empty.
func (reg *Registry) VerifySecret(clientID, secret string) (bool, error) {
	var secretHash string
	err := reg.db.QueryRow("SELECT client_secret FROM clients WHERE client_id = ?", clientID).Scan(&secretHash)
	if err != nil {
		return false, fmt.Errorf("client not found: %w", err)
	}
	if secretHash == "" {
		return true, nil // public client
	}
	return bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(secret)) == nil, nil
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
			ClientID           string   `json:"client_id,omitempty"`
			ClientName         string   `json:"client_name"`
			ClientSecret       string   `json:"client_secret,omitempty"`
			RedirectURIs       []string `json:"redirect_uris"`
			RequiredAttributes []string `json:"required_attributes,omitempty"`
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
			client, err = reg.RegisterWithID(req.ClientID, req.ClientName, req.RedirectURIs, req.ClientSecret, req.RequiredAttributes)
		} else {
			client, err = reg.Register(req.ClientName, req.RedirectURIs, req.ClientSecret, req.RequiredAttributes)
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

// HandleSetBilling handles POST /clients/{id}/billing — flag a client as a
// billable relying party and link its management-service billing account +
// rp_id. Admin-token gated, like registration.
//
//	Request: {"billable_rp": true, "billing_account_id": "<uuid>", "rp_id": "..."}
func HandleSetBilling(reg *Registry, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminToken != "" {
			auth := r.Header.Get("Authorization")
			if len(auth) < 8 || auth[7:] != adminToken {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		clientID := r.PathValue("id")
		if clientID == "" {
			http.Error(w, `{"error":"client id required"}`, http.StatusBadRequest)
			return
		}
		var req struct {
			BillableRP       bool   `json:"billable_rp"`
			BillingAccountID string `json:"billing_account_id"`
			RPID             string `json:"rp_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		if req.BillableRP && req.BillingAccountID == "" {
			http.Error(w, `{"error":"billing_account_id required when billable_rp is true"}`, http.StatusBadRequest)
			return
		}
		client, err := reg.SetBilling(clientID, req.BillableRP, req.BillingAccountID, req.RPID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(client)
	}
}
