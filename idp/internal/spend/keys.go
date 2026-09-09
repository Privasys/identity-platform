// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package spend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// WellKnownPath is where a spending app publishes its spend-key JWKS. For a
// platform app it is served from the app's enclave origin
// (https://<app>.apps.privasys.org/.well-known/privasys-spend-keys.json): the
// TLS endpoint terminates inside the app's enclave, so the key set is the
// running workload's own statement. A non-enclave relying party registers
// a jwks_uri on its OIDC client instead.
const WellKnownPath = "/.well-known/privasys-spend-keys.json"

// JWK is the public half of an app's P-256 spend key as it travels in the
// app's JWKS and in the token's `cnf`.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// PublicKey decodes the JWK into an ECDSA P-256 public key.
func (k JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("spend: unsupported key type %s/%s", k.Kty, k.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("spend: jwk x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("spend: jwk y: %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("spend: jwk point is not on P-256")
	}
	return pub, nil
}

// Cnf returns the minimal `cnf.jwk` form (kty/crv/x/y + kid) a callee
// compares the proof key against.
func (k JWK) Cnf() map[string]any {
	out := map[string]any{"kty": "EC", "crv": "P-256", "x": k.X, "y": k.Y}
	if k.Kid != "" {
		out["kid"] = k.Kid
	}
	return out
}

// AppResolver maps a spender id to the URL of its JWKS. Platform apps
// resolve through the management-service (app id → enclave hostname → the
// well-known path); non-enclave relying parties through the client
// registry's jwks_uri.
type AppResolver interface {
	// JWKSURL returns where appID publishes its spend keys, plus a display
	// name and host for consent rows. ErrUnknownApp when nothing claims it.
	JWKSURL(ctx context.Context, appID string) (jwksURL, name, host string, err error)
}

// ErrUnknownApp is returned by an AppResolver for an id nothing claims.
var ErrUnknownApp = errors.New("spend: unknown app")

// keyCache fetches and caches per-app JWKS. Keys are refreshed on a kid
// miss (an app that restarted has a new key) but at most once per
// refetchMin, so a caller cannot make the IdP hammer an app's origin.
type keyCache struct {
	resolver AppResolver
	http     *http.Client
	ttl      time.Duration
	refetch  time.Duration

	mu      sync.Mutex
	entries map[string]*keyEntry
}

type keyEntry struct {
	keys      map[string]JWK
	fetchedAt time.Time
}

func newKeyCache(r AppResolver, client *http.Client) *keyCache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &keyCache{
		resolver: r,
		http:     client,
		ttl:      10 * time.Minute,
		refetch:  30 * time.Second,
		entries:  map[string]*keyEntry{},
	}
}

// Key returns appID's published key kid, fetching the JWKS as needed.
func (c *keyCache) Key(ctx context.Context, appID, kid string) (JWK, error) {
	c.mu.Lock()
	e := c.entries[appID]
	c.mu.Unlock()
	now := time.Now()
	if e != nil && now.Sub(e.fetchedAt) < c.ttl {
		if k, ok := e.keys[kid]; ok {
			return k, nil
		}
		if now.Sub(e.fetchedAt) < c.refetch {
			return JWK{}, fmt.Errorf("spend: app %s publishes no key %q", appID, kid)
		}
	}
	keys, err := c.fetch(ctx, appID)
	if err != nil {
		if e != nil {
			if k, ok := e.keys[kid]; ok {
				return k, nil // stale set beats an outage
			}
		}
		return JWK{}, err
	}
	c.mu.Lock()
	c.entries[appID] = &keyEntry{keys: keys, fetchedAt: now}
	c.mu.Unlock()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return JWK{}, fmt.Errorf("spend: app %s publishes no key %q", appID, kid)
}

func (c *keyCache) fetch(ctx context.Context, appID string) (map[string]JWK, error) {
	jwksURL, _, _, err := c.resolver.JWKSURL(ctx, appID)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(jwksURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("spend: app %s has no usable jwks url", appID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("spend: fetch %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spend: fetch %s: status %d", jwksURL, resp.StatusCode)
	}
	var doc struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("spend: parse jwks: %w", err)
	}
	out := map[string]JWK{}
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		if k.Kid == "" {
			k.Kid = Thumbprint(k)
		}
		out[k.Kid] = k
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("spend: %s publishes no P-256 key", jwksURL)
	}
	return out, nil
}

// Thumbprint is the RFC 7638 JWK thumbprint (base64url SHA-256 over the
// canonical {crv,kty,x,y} members), the kid convention every spend signer
// uses so a key is named the same way by everyone who sees it.
func Thumbprint(k JWK) string {
	canon := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, k.X, k.Y)
	return base64.RawURLEncoding.EncodeToString(sha256Sum([]byte(canon)))
}

// MgmtResolver resolves platform apps through the management-service's
// internal app lookup (IDP_MGMT_URL / IDP_MGMT_TOKEN), and non-platform
// spenders through an optional client-registry lookup.
type MgmtResolver struct {
	MgmtURL string
	Token   string
	// Extra management services to ask when the primary does not know the
	// app: one IdP serves several platform environments (prod and dev), and
	// an app id belongs to exactly one of them.
	Extra []MgmtBase
	HTTP  *http.Client
	// ClientJWKS, when set, resolves a non-platform spender (an OIDC
	// client id) to its registered jwks_uri and display name.
	ClientJWKS func(clientID string) (jwksURI, name string, ok bool)
}

// MgmtBase is one management-service origin and its internal token.
type MgmtBase struct {
	URL   string
	Token string
}

// JWKSURL implements AppResolver.
func (m *MgmtResolver) JWKSURL(ctx context.Context, appID string) (string, string, string, error) {
	if !IsPlatformAppID(appID) {
		if m.ClientJWKS != nil {
			if uri, name, ok := m.ClientJWKS(appID); ok && uri != "" {
				return uri, name, hostOf(uri), nil
			}
		}
		return "", "", "", ErrUnknownApp
	}
	bases := make([]MgmtBase, 0, 1+len(m.Extra))
	if m.MgmtURL != "" && m.Token != "" {
		bases = append(bases, MgmtBase{URL: m.MgmtURL, Token: m.Token})
	}
	for _, b := range m.Extra {
		if b.URL != "" && b.Token != "" {
			bases = append(bases, b)
		}
	}
	if len(bases) == 0 {
		return "", "", "", errors.New("spend: management-service not configured")
	}
	var lastErr error = ErrUnknownApp
	for _, b := range bases {
		jwks, name, host, err := m.resolveAt(ctx, b, appID)
		if err == nil {
			return jwks, name, host, nil
		}
		if !errors.Is(err, ErrUnknownApp) {
			lastErr = err
		}
	}
	return "", "", "", lastErr
}

func (m *MgmtResolver) resolveAt(ctx context.Context, b MgmtBase, appID string) (string, string, string, error) {
	client := m.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(b.URL, "/")+"/api/v1/internal/apps/"+appID, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+b.Token)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("spend: resolve app: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", "", "", ErrUnknownApp
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("spend: resolve app: status %d", resp.StatusCode)
	}
	var out struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Hostname    string `json:"hostname"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&out); err != nil {
		return "", "", "", fmt.Errorf("spend: resolve app: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(out.Hostname))
	if host == "" {
		return "", "", "", fmt.Errorf("spend: app %s is not deployed", appID)
	}
	name := out.DisplayName
	if name == "" {
		name = out.Name
	}
	return "https://" + host + WellKnownPath, name, host, nil
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}
