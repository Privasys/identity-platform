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
	return iss.IssueAccessTokenWithTTL(subject, audience, sid, roles, attributes, 15*time.Minute)
}

// IssueAccessTokenWithTTL is IssueAccessTokenWithSID with an explicit
// lifetime, used for long-lived infrastructure service-account tokens
// (e.g. the vault constellation's attestation-server bearer).
func (iss *Issuer) IssueAccessTokenWithTTL(subject, audience, sid string, roles []string, attributes map[string]string, ttl time.Duration) (string, error) {
	now := time.Now()
	c := jwt.MapClaims{
		"iss": iss.issuerURL,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
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

// IssueVaultApprovalToken issues a short-lived, operation-bound access token
// for the Enclave Vault promote step-up (the vault promote-step-up design). The caller
// proved a fresh WebAuthn assertion bound to `vaultOp`, so the token carries
// `amr:["webauthn"]` plus the `vault_op`/`nonce` the vault recomputes and
// checks against the operation it is being asked to promote. `iat`/`exp` are
// fixed by the begin step (they are inputs to the binding) and passed through
// verbatim.
func (iss *Issuer) IssueVaultApprovalToken(subject, audience, vaultOp, nonce string, iat, exp int64) (string, error) {
	c := jwt.MapClaims{
		"iss":      iss.issuerURL,
		"sub":      subject,
		"aud":      audience,
		"iat":      iat,
		"exp":      exp,
		"typ":      "at+jwt",
		"amr":      []string{"webauthn"},
		"vault_op": vaultOp,
		"nonce":    nonce,
	}
	return iss.sign(c)
}

// KeyCreationGrant carries the claims of a vault key-creation grant. The
// owner (`sub`) holds governance of the key; the caller presenting the grant
// to the vault only holds the material and is bound to it by attested app-id
// (OID 3.6 == the scope's app-id) or a holder-of-key `cnf`.
type KeyCreationGrant struct {
	Owner      string          // the privasys.id sub that governs the key
	Scope      string          // e.g. apps.privasys.org/<app-id> or users/<sub>
	KeyType    string          // Aes256GcmKey | P256SigningKey | HmacSha256Key
	Exportable bool            // whether the key may ever be exported
	Policy     json.RawMessage // the full vault KeyPolicy, embedded verbatim
	CnfX5tS256 string          // optional base64url SHA-256 of the caller's RA-TLS leaf
	Exp        int64           // expiry (unix seconds)
}

// IssueKeyCreationGrant signs a single-call vault key-creation grant
// (`aud = privasys-vault-keycreate`). The policy is embedded verbatim; the
// vault validates it and checks that its owner principal matches `sub`.
func (iss *Issuer) IssueKeyCreationGrant(g KeyCreationGrant) (string, error) {
	now := time.Now().Unix()
	c := jwt.MapClaims{
		"iss":        iss.issuerURL,
		"aud":        "privasys-vault-keycreate",
		"sub":        g.Owner,
		"scope":      g.Scope,
		"key_type":   g.KeyType,
		"exportable": g.Exportable,
		"policy":     g.Policy,
		"iat":        now,
		"exp":        g.Exp,
	}
	if g.CnfX5tS256 != "" {
		c["cnf"] = map[string]string{"x5t#S256": g.CnfX5tS256}
	}
	return iss.sign(c)
}

// WIAClaims are the claims of a Wallet Instance Attestation (WIA). The WIA
// identifies a wallet INSTANCE, never an account (§3.3 of attribute-billing):
// `cnf.jwk` is the attested, pairwise-neutral hardware holder key and there is
// no `sub`. A verifier requires a valid WIA (and cnf.jwk == holder_pub) before
// issuing an IVR or a disclosure, so free identity verification is wallet-only
// by construction.
type WIAClaims struct {
	HolderJWK     map[string]interface{} // cnf.jwk — the attested hardware holder key
	Level         string                 // attested security level (strongbox|tee|app-attest)
	Platform      string                 // ios | android
	WalletVersion string
	TTL           time.Duration
}

// VoucherClaims are the claims of a paid disclosure voucher (the attribute
// marketplace toll booth). The IdP mints one at attribute-request time after
// reserving the RP's credits; the wallet passes it to the issuing enclave,
// which refuses to mint a disclosure without a valid voucher and stamps its
// `jti` into the token evidence. It carries NO user identity — only the paying
// RP, the provider it is spent with, and the claims it covers (§7 privacy
// invariants).
type VoucherClaims struct {
	JTI      string   // reservation key + evidence anchor (ledger settles on this)
	RPID     string   // the paying relying party; the enclave checks == request rp_id
	Provider string   // provider namespace; the enclave checks == its own provider
	Claims   []string // namespaced attribute keys this voucher covers
	Credits  int64    // total price reserved (audit; the enclave does not price)
	TTL      time.Duration
}

// IssueVoucher signs a disclosure voucher with the IdP's OIDC key (typ =
// "voucher+jwt"); the issuing enclave verifies it against the IdP JWKS
// provisioned into it (like the CSCA anchors and the wallet-provider JWKS).
func (iss *Issuer) IssueVoucher(c VoucherClaims) (string, error) {
	now := time.Now()
	ttl := c.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	claims := jwt.MapClaims{
		"iss":      iss.issuerURL,
		"iat":      now.Unix(),
		"exp":      now.Add(ttl).Unix(),
		"jti":      c.JTI,
		"rp_id":    c.RPID,
		"provider": c.Provider,
		"claims":   c.Claims,
		"credits":  c.Credits,
		"v":        1,
	}
	return iss.signTyp(claims, "voucher+jwt")
}

// IssueWIA signs a Wallet Instance Attestation with the wallet-provider key
// (typ = "wia+jwt"). Verifiers resolve the signing key via the wallet-provider
// JWKS provisioned into them (like the CSCA anchors) and check cnf.jwk against
// the holder key presented on the request.
func (iss *Issuer) IssueWIA(c WIAClaims) (string, error) {
	now := time.Now()
	ttl := c.TTL
	if ttl <= 0 {
		ttl = 48 * time.Hour
	}
	claims := jwt.MapClaims{
		"iss": iss.issuerURL,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"cnf": map[string]interface{}{"jwk": c.HolderJWK},
	}
	if c.Level != "" {
		claims["level"] = c.Level
	}
	if c.Platform != "" {
		claims["platform"] = c.Platform
	}
	if c.WalletVersion != "" {
		claims["wallet_version"] = c.WalletVersion
	}
	return iss.signTyp(claims, "wia+jwt")
}

// ECPublicJWK renders a P-256 public key as a minimal EC public JWK
// (kty/crv/x/y with fixed 32-byte coordinates) — the exact `cnf.jwk` shape the
// verifier compares against the holder key it is handed.
func ECPublicJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x[32-len(xBytes):], xBytes)
	copy(y[32-len(yBytes):], yBytes)
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
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

// signTyp is sign with an explicit JOSE `typ` header (e.g. "wia+jwt").
func (iss *Issuer) signTyp(claims map[string]interface{}, typ string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	token.Header["kid"] = iss.keyID
	if typ != "" {
		token.Header["typ"] = typ
	}
	return token.SignedString(iss.privateKey)
}

// SignRaw produces an ES256 (ECDSA-P-256-SHA-256) signature over the
// given message bytes using the issuer's signing key, returning the
// raw 64-byte R||S concatenation (NOT DER). Used to co-sign EncAuth
// vouchers so enclaves can verify them with the same JWKS they
// already trust for JWT verification.
func (iss *Issuer) SignRaw(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, iss.privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	curveByteLen := (iss.privateKey.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*curveByteLen)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[curveByteLen-len(rb):curveByteLen], rb)
	copy(out[2*curveByteLen-len(sb):], sb)
	return out, nil
}

// PublicKey returns the issuer's signing public key. Callers can use
// this to verify SignRaw outputs locally (e.g. in tests).
func (iss *Issuer) PublicKey() *ecdsa.PublicKey {
	return &iss.privateKey.PublicKey
}

// KeyID returns the JWKS key id matching SignRaw outputs.
func (iss *Issuer) KeyID() string { return iss.keyID }

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
