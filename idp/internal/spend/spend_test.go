// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package spend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Privasys/idp/internal/sessions"
	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

const testIssuer = "https://idp.test"

type fixture struct {
	h        *Handler
	store    *Store
	sess     *sessions.Store
	issuer   *tokens.Issuer
	appKey   *ecdsa.PrivateKey
	appID    string
	jwksHits int
	resolver *staticResolver
}

type staticResolver struct {
	url  string
	name string
	host string
}

func (s *staticResolver) JWKSURL(_ context.Context, appID string) (string, string, string, error) {
	if !IsPlatformAppID(appID) {
		return "", "", "", ErrUnknownApp
	}
	return s.url, s.name, s.host, nil
}

func jwkOf(pub *ecdsa.PublicKey) JWK {
	m := tokens.ECPublicJWK(pub)
	k := JWK{Kty: "EC", Crv: "P-256", X: m["x"].(string), Y: m["y"].(string)}
	k.Kid = Thumbprint(k)
	return k
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	sess, err := sessions.New(db)
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(db, sess)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := tokens.NewIssuer(filepath.Join(t.TempDir(), "key.pem"), testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	appKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &fixture{store: st, sess: sess, issuer: iss, appKey: appKey,
		appID: "0123456789abcdef0123456789abcdef"}
	// The app's well-known JWKS.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits++
		if r.URL.Path != WellKnownPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []JWK{jwkOf(&appKey.PublicKey)}})
	}))
	t.Cleanup(srv.Close)
	f.resolver = &staticResolver{url: srv.URL + WellKnownPath, name: "Harness", host: strings.TrimPrefix(srv.URL, "https://")}
	f.h = New(Config{
		Store:    st,
		Issuer:   iss,
		Auth:     func(r *http.Request) (string, error) { return r.Header.Get("X-Test-User"), nil },
		Resolver: f.resolver,
		HTTP:     srv.Client(),
	})
	return f
}

func (f *fixture) assertion(t *testing.T, mutate func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": f.appID, "sub": f.appID, "aud": testIssuer + TokenPath,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": "j1",
	}
	if mutate != nil {
		mutate(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = jwkOf(&f.appKey.PublicKey).Kid
	tok.Header["typ"] = AssertionTyp
	s, err := tok.SignedString(f.appKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fixture) grant(t *testing.T, user string, cap int64) {
	t.Helper()
	body := strings.NewReader(`{"app_id":"` + f.appID + `","cap":` + jsonInt(cap) + `}`)
	r := httptest.NewRequest(http.MethodPost, "/spend/consents", body)
	r.Header.Set("X-Test-User", user)
	w := httptest.NewRecorder()
	f.h.HandleGrantConsent(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("grant: %d %s", w.Code, w.Body)
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func (f *fixture) token(t *testing.T, sub, assertion string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"sub": sub, "client_assertion": assertion})
	r := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.h.HandleToken(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestTokenRequiresConsent(t *testing.T) {
	f := newFixture(t)
	code, out := f.token(t, "user-1", f.assertion(t, nil))
	if code != http.StatusForbidden || out["error"] != "consent_required" {
		t.Fatalf("want 403 consent_required, got %d %v", code, out)
	}
}

func TestTokenIssuedAndBound(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "user-1", 500000)
	code, out := f.token(t, "user-1", f.assertion(t, nil))
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d %v", code, out)
	}
	tokStr, _ := out["spend_token"].(string)
	claims, err := f.issuer.VerifyAccessToken(tokStr)
	if err != nil {
		t.Fatalf("token does not verify against the issuer key: %v", err)
	}
	if claims["sub"] != "user-1" || claims["azp"] != f.appID {
		t.Fatalf("claims: %v", claims)
	}
	if cap, _ := claims["cap"].(float64); int64(cap) != 500000 {
		t.Fatalf("cap: %v", claims["cap"])
	}
	cnf, _ := claims["cnf"].(map[string]any)
	jwk, _ := cnf["jwk"].(map[string]any)
	want := jwkOf(&f.appKey.PublicKey)
	if jwk["x"] != want.X || jwk["y"] != want.Y || jwk["kid"] != want.Kid {
		t.Fatalf("cnf does not name the app key: %v", jwk)
	}
	sid, _ := claims["sid"].(string)
	if sid == "" || !f.sess.IsActive(sid) {
		t.Fatalf("token sid %q is not a live consent session", sid)
	}
	// typ header
	parts := strings.Split(tokStr, ".")
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !strings.Contains(string(hdr), `"typ":"spend+jwt"`) {
		t.Fatalf("header: %s", hdr)
	}
	// Second request reuses the cached JWKS.
	hits := f.jwksHits
	if code, _ := f.token(t, "user-1", f.assertion(t, nil)); code != http.StatusOK {
		t.Fatal("second token")
	}
	if f.jwksHits != hits {
		t.Fatalf("JWKS refetched: %d → %d", hits, f.jwksHits)
	}
}

func TestTokenRefusedForForeignKey(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "user-1", 0)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": f.appID, "sub": f.appID, "aud": testIssuer + TokenPath,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "x",
	})
	tok.Header["kid"] = jwkOf(&other.PublicKey).Kid
	s, _ := tok.SignedString(other)
	if code, out := f.token(t, "user-1", s); code != http.StatusUnauthorized {
		t.Fatalf("want 401 for a key the app never published, got %d %v", code, out)
	}
}

func TestTokenRefusedForWrongAudienceAndLongExp(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "user-1", 0)
	if code, _ := f.token(t, "user-1", f.assertion(t, func(c jwt.MapClaims) { c["aud"] = "https://other" })); code != http.StatusUnauthorized {
		t.Fatalf("aud: want 401, got %d", code)
	}
	if code, _ := f.token(t, "user-1", f.assertion(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(time.Hour).Unix() })); code != http.StatusUnauthorized {
		t.Fatalf("exp: want 401, got %d", code)
	}
	if code, _ := f.token(t, "user-1", f.assertion(t, func(c jwt.MapClaims) { delete(c, "jti") })); code != http.StatusUnauthorized {
		t.Fatalf("jti: want 401, got %d", code)
	}
}

func TestRevokeEndsTokens(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "user-1", 0)
	code, out := f.token(t, "user-1", f.assertion(t, nil))
	if code != http.StatusOK {
		t.Fatal(code)
	}
	sid, _ := out["sid"].(string)

	r := httptest.NewRequest(http.MethodDelete, "/spend/consents/"+f.appID, nil)
	r.SetPathValue("app_id", f.appID)
	r.Header.Set("X-Test-User", "user-1")
	w := httptest.NewRecorder()
	f.h.HandleRevokeConsent(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if f.sess.IsActive(sid) {
		t.Fatal("consent session still active after revoke")
	}
	revoked, _ := f.sess.ListRevokedSince(0)
	if len(revoked) != 1 || revoked[0] != sid {
		t.Fatalf("revoked feed: %v", revoked)
	}
	if code, out := f.token(t, "user-1", f.assertion(t, nil)); code != http.StatusForbidden {
		t.Fatalf("after revoke: want 403, got %d %v", code, out)
	}
	// Re-granting mints a fresh consent session.
	f.grant(t, "user-1", 10)
	if code, out := f.token(t, "user-1", f.assertion(t, nil)); code != http.StatusOK || out["sid"] == sid {
		t.Fatalf("regrant: %d %v", code, out)
	}
}

func TestListAndGetConsents(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "user-1", 42)
	r := httptest.NewRequest(http.MethodGet, "/spend/consents", nil)
	r.Header.Set("X-Test-User", "user-1")
	w := httptest.NewRecorder()
	f.h.HandleListConsents(w, r)
	var out struct {
		Consents []Consent `json:"consents"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Consents) != 1 || out.Consents[0].AppID != f.appID || out.Consents[0].Cap != 42 || out.Consents[0].AppName != "Harness" {
		t.Fatalf("list: %s", w.Body)
	}
	// Another user sees nothing.
	r2 := httptest.NewRequest(http.MethodGet, "/spend/consents/"+f.appID, nil)
	r2.SetPathValue("app_id", f.appID)
	r2.Header.Set("X-Test-User", "user-2")
	w2 := httptest.NewRecorder()
	f.h.HandleGetConsent(w2, r2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("other user: %d", w2.Code)
	}
}

func TestGrantRenewsKeepsSID(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "user-1", 1)
	c1, _ := f.store.Get("user-1", f.appID)
	f.grant(t, "user-1", 2)
	c2, _ := f.store.Get("user-1", f.appID)
	if c1.SID != c2.SID || c2.Cap != 2 {
		t.Fatalf("renew: %+v → %+v", c1, c2)
	}
}

func TestNormaliseAppID(t *testing.T) {
	if got := NormaliseAppID("01234567-89AB-CDEF-0123-456789abcdef"); got != "0123456789abcdef0123456789abcdef" {
		t.Fatal(got)
	}
	if got := NormaliseAppID(" my-client "); got != "my-client" {
		t.Fatal(got)
	}
}
