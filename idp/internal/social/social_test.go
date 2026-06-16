// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package social

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/oidc"
)

// fakeProvider stands in for an upstream OAuth provider: a token endpoint that
// returns an access token and a userinfo endpoint that returns claims.
func fakeProvider(t *testing.T) (*httptest.Server, *Provider) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("code_verifier") == "" {
			t.Error("upstream token exchange missing PKCE code_verifier")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"fake-at","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sub":"u-123","name":"Alice","email":"alice@example.com","email_verified":true}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	prov := &Provider{
		Name: "google", DisplayName: "Google",
		AuthURL:     srv.URL + "/authorize",
		TokenURL:    srv.URL + "/token",
		UserInfoURL: srv.URL + "/userinfo",
		ClientID:    "cid", ClientSecret: "secret",
		Scopes: []string{"openid", "email", "profile"},
		PKCE:   true,
	}
	return srv, prov
}

func newWalletTestHandler(t *testing.T, prov *Provider) *Handler {
	t.Helper()
	providers := NewProviders()
	providers.Register(prov)
	return NewHandler(providers, oidc.NewCodeStore(), oidc.NewSessionStore(), "https://privasys.id")
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Full happy path: /wallet/link -> (provider) -> /auth/social/callback ->
// redirect to wallet -> /wallet/link/result returns the attributes.
func TestWalletLink_FullFlow(t *testing.T) {
	_, prov := fakeProvider(t)
	h := newWalletTestHandler(t, prov)

	const walletVerifier = "wallet-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const nonce = "nonce-123"

	// 1. /wallet/link -> 302 to provider authorize with PKCE challenge.
	linkURL := "/wallet/link?provider=google&redirect_uri=" +
		url.QueryEscape("privasys-wallet://link/callback") +
		"&nonce=" + nonce + "&code_challenge=" + s256(walletVerifier) + "&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	h.HandleWalletLink(rec, httptest.NewRequest("GET", linkURL, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("HandleWalletLink: got %d, want 302; body=%s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code_challenge") == "" || loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL missing upstream PKCE: %s", loc)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in authorize URL")
	}

	// 2. Provider redirects back to /auth/social/callback?code=..&state=..
	rec = httptest.NewRecorder()
	h.HandleCallback(rec, httptest.NewRequest("GET", "/auth/social/callback?code=prov-code&state="+state, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("HandleCallback: got %d, want 302; body=%s", rec.Code, rec.Body)
	}
	cb, _ := url.Parse(rec.Header().Get("Location"))
	if cb.Scheme != "privasys-wallet" {
		t.Fatalf("callback redirect scheme = %q, want privasys-wallet", cb.Scheme)
	}
	if cb.Query().Get("nonce") != nonce {
		t.Fatalf("nonce not echoed: got %q", cb.Query().Get("nonce"))
	}
	resultCode := cb.Query().Get("code")
	if resultCode == "" {
		t.Fatal("no result code in wallet redirect")
	}

	// 3. /wallet/link/result with the right verifier -> attributes.
	rec = httptest.NewRecorder()
	h.HandleWalletLinkResult(rec, httptest.NewRequest("GET",
		"/wallet/link/result?code="+resultCode+"&code_verifier="+walletVerifier, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleWalletLinkResult: got %d, want 200; body=%s", rec.Code, rec.Body)
	}
	var out struct {
		Provider   string           `json:"provider"`
		Sub        string           `json:"sub"`
		Attributes []walletLinkAttr `json:"attributes"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if out.Sub != "google:u-123" {
		t.Errorf("sub = %q, want google:u-123", out.Sub)
	}
	got := map[string]walletLinkAttr{}
	for _, a := range out.Attributes {
		got[a.Key] = a
	}
	if got["email"].Value != "alice@example.com" || !got["email"].Verified {
		t.Errorf("email attr = %+v, want verified alice@example.com", got["email"])
	}
	if got["name"].Value != "Alice" || got["name"].Verified {
		t.Errorf("name attr = %+v, want unverified Alice", got["name"])
	}

	// 4. The result code is single-use.
	rec = httptest.NewRecorder()
	h.HandleWalletLinkResult(rec, httptest.NewRequest("GET",
		"/wallet/link/result?code="+resultCode+"&code_verifier="+walletVerifier, nil))
	if rec.Code == http.StatusOK {
		t.Error("result code was redeemable twice; want single-use")
	}
}

func TestWalletLink_RejectsBadRedirectScheme(t *testing.T) {
	_, prov := fakeProvider(t)
	h := newWalletTestHandler(t, prov)
	rec := httptest.NewRecorder()
	h.HandleWalletLink(rec, httptest.NewRequest("GET",
		"/wallet/link?provider=google&redirect_uri="+url.QueryEscape("https://evil.example/cb")+
			"&nonce=n&code_challenge="+s256("v")+"&code_challenge_method=S256", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 for disallowed redirect scheme", rec.Code)
	}
}

func TestWalletLink_RequiresPKCE(t *testing.T) {
	_, prov := fakeProvider(t)
	h := newWalletTestHandler(t, prov)
	rec := httptest.NewRecorder()
	h.HandleWalletLink(rec, httptest.NewRequest("GET",
		"/wallet/link?provider=google&redirect_uri="+url.QueryEscape("privasys-wallet://link/callback")+"&nonce=n", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 when code_challenge is absent", rec.Code)
	}
}

func TestWalletLinkResult_RejectsWrongVerifier(t *testing.T) {
	_, prov := fakeProvider(t)
	h := newWalletTestHandler(t, prov)

	linkURL := "/wallet/link?provider=google&redirect_uri=" +
		url.QueryEscape("privasys-wallet://link/callback") +
		"&nonce=n&code_challenge=" + s256("right-verifier-xxxxxxxxxxxxxxxxxxxxxxxxxx") + "&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	h.HandleWalletLink(rec, httptest.NewRequest("GET", linkURL, nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")

	rec = httptest.NewRecorder()
	h.HandleCallback(rec, httptest.NewRequest("GET", "/auth/social/callback?code=c&state="+state, nil))
	cb, _ := url.Parse(rec.Header().Get("Location"))
	resultCode := cb.Query().Get("code")

	rec = httptest.NewRecorder()
	h.HandleWalletLinkResult(rec, httptest.NewRequest("GET",
		"/wallet/link/result?code="+resultCode+"&code_verifier=wrong-verifier", nil))
	if rec.Code == http.StatusOK {
		t.Error("result redeemed with wrong PKCE verifier; want rejection")
	}
	if !strings.Contains(rec.Body.String(), "PKCE") {
		t.Errorf("expected PKCE error, got %s", rec.Body)
	}
}
