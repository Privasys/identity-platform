// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package tokens handles ES256 JWT signing and JWKS publication.
package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// IssuerURL returns the configured issuer URL.
func (iss *Issuer) IssuerURL() string {
	return iss.issuerURL
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

	// SID is the unified per-(user, app, device) session id (see
	// `internal/sessions`). When non-empty it is emitted as a top-level
	// `sid` claim on every issued ID/access token. The wallet, the
	// gateway, and resource servers use it as the revocation handle.
	SID string

	// SessionRelay, if set, is emitted into the JWT as a top-level
	// `session` claim plus optional `att_verified` / `att_quote_hash` /
	// `att_oids` claims when those keys are present. Carries the
	// browser→enclave session metadata captured by the wallet during a
	// `mode:"session-relay"` flow.
	SessionRelay map[string]interface{}
}

// IssueIDToken creates a signed OIDC ID token.
func (iss *Issuer) IssueIDToken(claims IDTokenClaims) (string, error) {
	now := time.Now()
	c := jwt.MapClaims{
		"iss":               iss.issuerURL,
		"sub":               claims.Subject,
		"aud":               claims.Audience,
		"iat":               now.Unix(),
		"exp":               now.Add(15 * time.Minute).Unix(),
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
	if claims.SID != "" {
		c["sid"] = claims.SID
	}
	// Browser→enclave session relay metadata (optional). Pulls a
	// well-known subset of keys to the top level for downstream
	// consumers; the full session object is also embedded as `session`.
	if sr := claims.SessionRelay; len(sr) > 0 {
		if v, ok := sr["att_verified"]; ok {
			c["att_verified"] = v
		}
		if v, ok := sr["att_quote_hash"]; ok {
			c["att_quote_hash"] = v
		}
		if v, ok := sr["att_oids"]; ok {
			c["att_oids"] = v
		}
		if v, ok := sr["session"]; ok {
			c["session"] = v
		}
	}
	return iss.sign(c)
}

// IssueAccessToken creates a signed access token (JWT) with optional role and profile claims.
func (iss *Issuer) IssueAccessToken(subject, audience string, roles []string, attributes map[string]string) (string, error) {
	return iss.IssueAccessTokenWithSID(subject, audience, "", roles, attributes)
}

// IssueAccessTokenWithSID is IssueAccessToken plus a top-level `sid`
// claim binding the token to a row in `internal/sessions`. Resource
// servers use this to enforce wallet-driven revocation.
func (iss *Issuer) IssueAccessTokenWithSID(subject, audience, sid string, roles []string, attributes map[string]string) (string, error) {
	now := time.Now()
	c := jwt.MapClaims{
		"iss": iss.issuerURL,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
		"typ": "at+jwt",
	}
	if sid != "" {
		c["sid"] = sid
	}
	if len(roles) > 0 {
		c["roles"] = roles
	}
	for k, v := range attributes {
		if v != "" {
			c[k] = v
		}
	}
	return iss.sign(c)
}

// VerifyAccessToken parses and validates a JWT signed by this issuer.
func (iss *Issuer) VerifyAccessToken(tokenStr string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &iss.privateKey.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// VerifyServiceAccountJWT verifies a JWT assertion signed by a service account's RSA key.
func VerifyServiceAccountJWT(tokenStr string, publicKeyPEM string, expectedAudience string) (map[string]interface{}, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in service account public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"})}
	if expectedAudience != "" {
		opts = append(opts, jwt.WithAudience(expectedAudience))
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return rsaPub, nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func (iss *Issuer) sign(claims map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	token.Header["kid"] = iss.keyID
	return token.SignedString(iss.privateKey)
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
