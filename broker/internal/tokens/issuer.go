// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package tokens issues short-lived JWTs for the attestation server.
//
// The broker acts as a lightweight OIDC provider: it signs JWTs with an
// ECDSA P-256 private key and exposes /.well-known/openid-configuration
// and /jwks endpoints so the attestation server can validate the tokens
// via standard OIDC discovery.
package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	privateKey *ecdsa.PrivateKey
	keyID      string
	issuerURL  string // e.g. https://relay.privasys.org
	audience   string // attestation server audience
	role       string // required role claim
}

// Config for creating an Issuer.
type Config struct {
	// PrivateKeyPEM is an EC P-256 private key in PEM format.
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

	var privKey *ecdsa.PrivateKey
	// Try PKCS#8 first, then SEC1 (EC PRIVATE KEY).
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		privKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not ECDSA")
		}
	} else if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		privKey = key
	} else {
		return nil, fmt.Errorf("failed to parse EC private key: %v", err)
	}

	if privKey.Curve != elliptic.P256() {
		return nil, errors.New("only P-256 keys are supported (ES256)")
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
		"alg": "ES256",
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
	r, s, err := ecdsa.Sign(rand.Reader, iss.privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// ES256 signature is r || s, each zero-padded to 32 bytes.
	curveBits := iss.privateKey.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8
	sig := make([]byte, 2*keyBytes)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(sig[2*keyBytes-len(sBytes):], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

// HandleJWKS returns the JWKS endpoint handler.
func (iss *Issuer) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := iss.privateKey.PublicKey
	resp := map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "EC",
				"use": "sig",
				"alg": "ES256",
				"crv": "P-256",
				"kid": iss.keyID,
				"x":   base64.RawURLEncoding.EncodeToString(padToKeySize(pub.X, 32)),
				"y":   base64.RawURLEncoding.EncodeToString(padToKeySize(pub.Y, 32)),
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
		"id_token_signing_alg_values_supported": []string{"ES256"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(resp)
}

// padToKeySize left-pads b with zeros to reach size bytes.
func padToKeySize(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}
