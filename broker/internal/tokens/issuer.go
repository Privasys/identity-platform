// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package tokens issues short-lived JWTs for the attestation server.
//
// The broker acts as a lightweight OIDC provider: it signs JWTs with an
// RSA private key and exposes /.well-known/openid-configuration and /jwks
// endpoints so the attestation server can validate the tokens via standard
// OIDC discovery.
package tokens

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// Issuer manages JWT signing and JWKS publication.
type Issuer struct {
	privateKey *rsa.PrivateKey
	keyID      string
	issuerURL  string // e.g. https://relay.privasys.org
	audience   string // attestation server audience
	role       string // required role claim
}

// Config for creating an Issuer.
type Config struct {
	// PrivateKeyPEM is an RSA private key in PEM format.
	PrivateKeyPEM string

	// IssuerURL is the public URL of this broker (used as JWT "iss").
	IssuerURL string

	// Audience is the attestation server's expected "aud" claim.
	Audience string

	// Role is the role claim to include in issued tokens.
	Role string
}

// NewIssuer creates a JWT issuer from the given config.
func NewIssuer(cfg Config) (*Issuer, error) {
	if cfg.PrivateKeyPEM == "" {
		return nil, errors.New("SIGNING_KEY is required")
	}

	block, _ := pem.Decode([]byte(cfg.PrivateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block from SIGNING_KEY")
	}

	var privKey *rsa.PrivateKey
	// Try PKCS#8 first, then PKCS#1.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		privKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not RSA")
		}
	} else if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privKey = key
	} else {
		return nil, fmt.Errorf("failed to parse RSA private key: %v", err)
	}

	// Derive a stable key ID from the public key hash.
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	kidHash := sha256.Sum256(pubDER)
	keyID := base64.RawURLEncoding.EncodeToString(kidHash[:8])

	return &Issuer{
		privateKey: privKey,
		keyID:      keyID,
		issuerURL:  cfg.IssuerURL,
		audience:   cfg.Audience,
		role:       cfg.Role,
	}, nil
}

// Issue creates a signed JWT with a 5-minute lifetime.
func (iss *Issuer) Issue(subject string) (string, error) {
	now := time.Now()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": iss.keyID,
	}
	claims := map[string]interface{}{
		"iss":   iss.issuerURL,
		"sub":   subject,
		"aud":   iss.audience,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"roles": []string{iss.role},
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, iss.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

// HandleJWKS returns the JWKS endpoint handler.
func (iss *Issuer) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := iss.privateKey.PublicKey
	resp := map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": iss.keyID,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(resp)
}

// HandleOIDCDiscovery returns the OIDC discovery document.
func (iss *Issuer) HandleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"issuer":                                iss.issuerURL,
		"jwks_uri":                              iss.issuerURL + "/jwks",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(resp)
}
