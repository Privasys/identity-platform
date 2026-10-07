// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package spend

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// App proofs: an attested app calling this IdP for itself.
//
// An app that holds a spend key already signs per-request proofs for the
// services it calls (typ spend-proof+jwt: aud, iat, jti, signed with the key
// its JWKS publishes). Addressed to this IdP's host, the same proof
// authenticates the app here, so a new IdP endpoint for apps needs no new
// credential and no client-library release.

// proofTyp is the JOSE typ an app's spend library puts on a proof.
const proofTyp = "spend-proof+jwt"

// proofWindow bounds how old (or how far ahead) a proof's iat may be.
const proofWindow = 2 * time.Minute

// proofReplay remembers proof ids for as long as they would verify.
type proofReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (p *proofReplay) seenBefore(jti string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string]time.Time{}
	}
	for k, until := range p.seen {
		if now.After(until) {
			delete(p.seen, k)
		}
	}
	if _, ok := p.seen[jti]; ok {
		return true
	}
	p.seen[jti] = now.Add(2 * proofWindow)
	return false
}

var appProofReplay proofReplay

// VerifyAppProof authenticates appID from a proof addressed to this IdP and
// returns the app's display name as its platform registers it (never a name
// the app supplies about itself).
func (h *Handler) VerifyAppProof(ctx context.Context, appID, proof string) (string, error) {
	appID = NormaliseAppID(appID)
	if appID == "" || strings.TrimSpace(proof) == "" {
		return "", errors.New("app id and proof required")
	}
	host := ""
	if u, err := url.Parse(h.issuer.IssuerURL()); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(host))
	tok, err := parser.Parse(proof, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != proofTyp {
			return nil, errors.New("not an app proof")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("proof has no kid")
		}
		k, err := h.keys.Key(ctx, appID, kid)
		if err != nil {
			return nil, err
		}
		return k.PublicKey()
	})
	if err != nil {
		return "", fmt.Errorf("app proof: %w", err)
	}
	claims, _ := tok.Claims.(jwt.MapClaims)
	iat, err := claims.GetIssuedAt()
	now := h.now()
	if err != nil || iat == nil || iat.Time.Before(now.Add(-proofWindow)) || iat.Time.After(now.Add(proofWindow)) {
		return "", errors.New("app proof: stale or missing iat")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" || appProofReplay.seenBefore(appID+"/"+jti, now) {
		return "", errors.New("app proof: missing or replayed jti")
	}
	_, name, _, err := h.resolver.JWKSURL(ctx, appID)
	if err != nil {
		return "", err
	}
	return name, nil
}

// HasConsent reports whether sub has a live spend consent for appID: the
// standing relationship an app needs before it may ask the holder for
// anything on its own initiative.
func (h *Handler) HasConsent(sub, appID string) bool {
	_, err := h.store.Get(sub, NormaliseAppID(appID))
	return err == nil
}
