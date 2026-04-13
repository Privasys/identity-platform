// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package tokens handles ES256 JWT signing and JWKS publication.
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
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"
)

// Issuer signs JWTs and serves JWKS.
type Issuer struct {
	privateKey *ecdsa.PrivateKey
	keyID      string
	issuerURL  string
}

// NewIssuer loads an EC P-256 private key from a PEM file and creates an issuer.
// If the file does not exist, a new key is generated and saved.
func NewIssuer(keyPath, issuerURL string) (*Issuer, error) {
	var privKey *ecdsa.PrivateKey

	data, err := os.ReadFile(keyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		// Generate a new key.
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		// Save it.
		der, err := x509.MarshalECPrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key: %w", err)
		}
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(keyPath, pemBlock, 0o600); err != nil {
			return nil, fmt.Errorf("write key file: %w", err)
		}
	} else {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM block found in %s", keyPath)
		}
		// Try PKCS#8 then SEC1.
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			var ok bool
			privKey, ok = key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("PKCS#8 key is not ECDSA")
			}
		} else if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			privKey = key
		} else {
			return nil, fmt.Errorf("failed to parse EC key: %v", err)
		}
	}

	if privKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("only P-256 keys are supported")
	}

	// Derive stable key ID from public key hash.
	pubDER, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	h := sha256.Sum256(pubDER)
	keyID := base64.RawURLEncoding.EncodeToString(h[:8])

	return &Issuer{
		privateKey: privKey,
		keyID:      keyID,
		issuerURL:  issuerURL,
	}, nil
}

// IDTokenClaims are the claims included in an ID token.
type IDTokenClaims struct {
	Subject          string
	Email            string
	Name             string
	Picture          string
	AttestationLevel string
	Audience         string
	Nonce            string
	AuthTime         time.Time
}

// IssueIDToken creates a signed OIDC ID token.
func (iss *Issuer) IssueIDToken(claims IDTokenClaims) (string, error) {
	now := time.Now()
	c := map[string]interface{}{
		"iss":               iss.issuerURL,
		"sub":               claims.Subject,
		"aud":               claims.Audience,
		"iat":               now.Unix(),
		"exp":               now.Add(1 * time.Hour).Unix(),
		"auth_time":         claims.AuthTime.Unix(),
		"attestation_level": claims.AttestationLevel,
	}
	if claims.Email != "" {
		c["email"] = claims.Email
		c["email_verified"] = true
	}
	if claims.Name != "" {
		c["name"] = claims.Name
	}
	if claims.Picture != "" {
		c["picture"] = claims.Picture
	}
	if claims.Nonce != "" {
		c["nonce"] = claims.Nonce
	}
	return iss.sign(c)
}

// IssueAccessToken creates a signed access token (opaque JWT).
func (iss *Issuer) IssueAccessToken(subject, audience string) (string, error) {
	now := time.Now()
	c := map[string]interface{}{
		"iss": iss.issuerURL,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
		"typ": "at+jwt",
	}
	return iss.sign(c)
}

// VerifyAccessToken parses and validates a JWT, returning claims.
func (iss *Issuer) VerifyAccessToken(tokenStr string) (map[string]interface{}, error) {
	parts := splitJWT(tokenStr)
	if parts == nil {
		return nil, fmt.Errorf("malformed JWT")
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(signingInput))

	// ES256 signature is r || s, each 32 bytes.
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("invalid ES256 signature length: %d", len(sigBytes))
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(&iss.privateKey.PublicKey, hash[:], r, s) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	// Check expiry.
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token expired")
		}
	}

	return claims, nil
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	count := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
			count++
		}
	}
	if count == 2 {
		parts = append(parts, token[start:])
		return parts
	}
	return nil
}

func (iss *Issuer) sign(claims map[string]interface{}) (string, error) {
	header := map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": iss.keyID,
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

	// Fixed-size r || s (32 bytes each for P-256).
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

// HandleJWKS serves the public key in JWK Set format.
func (iss *Issuer) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := iss.privateKey.PublicKey

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	// Pad to 32 bytes.
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x[32-len(xBytes):], xBytes)
	copy(y[32-len(yBytes):], yBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"use": "sig",
				"alg": "ES256",
				"kid": iss.keyID,
				"x":   base64.RawURLEncoding.EncodeToString(x),
				"y":   base64.RawURLEncoding.EncodeToString(y),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwks)
}
