// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package social

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

// A client's registration is the ceiling on the providers its users may
// sign in with: the start path refuses one outside it and the listing shows
// only the allowed ones, so a page cannot widen the choice.
func TestClientPolicy_RestrictsStartAndListing(t *testing.T) {
	srv, prov := fakeProvider(t)
	_ = srv
	providers := NewProviders()
	providers.Register(prov)
	providers.Register(&Provider{Name: "microsoft", ClientID: "ms-id", AuthURL: prov.AuthURL, TokenURL: prov.TokenURL, Scopes: []string{"openid"}, PKCE: true})
	sessions := oidc.NewSessionStore()
	h := NewHandler(providers, oidc.NewCodeStore(), sessions, "https://privasys.id")
	h.SetClientPolicy(func(clientID string) []string {
		if clientID == "workplace" {
			return []string{"microsoft"}
		}
		return nil
	})
	sessions.Create(&oidc.AuthSession{SessionID: "s-work", ClientID: "workplace", ExpiresAt: time.Now().Add(time.Minute)})
	sessions.Create(&oidc.AuthSession{SessionID: "s-open", ClientID: "open", ExpiresAt: time.Now().Add(time.Minute)})

	start := func(provider, session string) int {
		rec := httptest.NewRecorder()
		h.HandleRedirect(rec, httptest.NewRequest("GET", "/auth/social?provider="+provider+"&session_id="+session, nil))
		return rec.Code
	}
	if code := start(prov.Name, "s-work"); code != http.StatusForbidden {
		t.Fatalf("a provider outside the client's list must be refused, got %d", code)
	}
	if code := start("microsoft", "s-work"); code != http.StatusFound {
		t.Fatalf("an allowed provider starts the sign-in, got %d", code)
	}
	if code := start(prov.Name, "s-open"); code != http.StatusFound {
		t.Fatalf("a client without a restriction may use any provider, got %d", code)
	}

	list := func(query string) []string {
		rec := httptest.NewRecorder()
		h.HandleProviders(rec, httptest.NewRequest("GET", "/auth/social/providers"+query, nil))
		var body struct {
			Providers []string `json:"providers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Providers
	}
	if got := list(""); len(got) != 2 {
		t.Fatalf("unnamed, every configured provider is listed: %v", got)
	}
	if got := list("?client_id=workplace"); len(got) != 1 || got[0] != "microsoft" {
		t.Fatalf("named for the client, only its providers are listed: %v", got)
	}
	if got := list("?session_id=s-work"); len(got) != 1 || got[0] != "microsoft" {
		t.Fatalf("named through its session, the same: %v", got)
	}
	if got := list("?client_id=open"); len(got) != 2 {
		t.Fatalf("an unrestricted client lists everything: %v", got)
	}
}

// A client's own registration: the start path sends the person to its
// endpoints with its upstream client id, the callback exchanges there with its
// credential and no platform secret, and another client stays on the platform's.
func TestFederatedRegistration(t *testing.T) {
	var form url.Values
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.ParseForm()
			form = r.PostForm
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/me":
			json.NewEncoder(w).Encode(map[string]string{"id": "directory-id", "mail": "ada@example.com"})
		}
	}))
	defer upstream.Close()

	providers := NewProviders()
	providers.Register(&Provider{Name: "microsoft", ClientID: "platform-id", ClientSecret: "platform-secret",
		AuthURL: upstream.URL + "/platform-auth", TokenURL: upstream.URL + "/platform-token", UserInfoURL: upstream.URL + "/me", PKCE: true})
	sessions := oidc.NewSessionStore()
	exp := time.Now().Add(time.Minute)
	sess, other := &oidc.AuthSession{SessionID: "own-session", ClientID: "own-client", ExpiresAt: exp}, &oidc.AuthSession{SessionID: "other-session", ClientID: "other-client", ExpiresAt: exp}
	sessions.Create(sess)
	sessions.Create(other)
	h := NewHandler(providers, oidc.NewCodeStore(), sessions, "https://idp.example")
	h.SetFederation(func(clientID, provider string, base *Provider) (*Provider, error) {
		if clientID != "own-client" {
			return nil, nil
		}
		p := *base
		p.ClientID, p.ClientSecret = "customer-id", ""
		p.AuthURL, p.TokenURL = upstream.URL+"/auth", upstream.URL+"/token"
		p.Credential = func(_ context.Context, f url.Values) error { f.Set("client_assertion", "signed"); return nil }
		return &p, nil
	}, func(clientID string) map[string]string {
		if clientID == "own-client" {
			return map[string]string{"microsoft": "Contoso"}
		}
		return nil
	})

	start := func(sid string) *url.URL {
		rec := httptest.NewRecorder()
		h.HandleRedirect(rec, httptest.NewRequest("GET", "/auth/social?provider=microsoft&session_id="+sid, nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("start: %d %s", rec.Code, rec.Body)
		}
		u, _ := url.Parse(rec.Header().Get("Location"))
		return u
	}
	own := start(sess.SessionID)
	if own.Query().Get("client_id") != "customer-id" || !strings.HasSuffix(own.Path, "/auth") {
		t.Fatalf("start path: %s", own)
	}
	plat := start(other.SessionID)
	if plat.Query().Get("client_id") != "platform-id" || !strings.HasSuffix(plat.Path, "/platform-auth") {
		t.Fatalf("another client: %s", plat)
	}

	rec := httptest.NewRecorder()
	h.HandleCallback(rec, httptest.NewRequest("GET", "/auth/social/callback?code=x&state="+own.Query().Get("state"), nil))
	if form == nil {
		t.Fatalf("no exchange at the client's token endpoint: %d %s", rec.Code, rec.Body)
	}
	if form.Get("client_id") != "customer-id" || form.Get("client_assertion") != "signed" || form.Has("client_secret") {
		t.Fatalf("exchange: %v", form)
	}

	rec = httptest.NewRecorder()
	h.HandleProviders(rec, httptest.NewRequest("GET", "/auth/social/providers?client_id=own-client", nil))
	if !strings.Contains(rec.Body.String(), "Contoso") {
		t.Fatalf("listing: %s", rec.Body)
	}
	rec = httptest.NewRecorder()
	h.HandleProviders(rec, httptest.NewRequest("GET", "/auth/social/providers?client_id=other-client", nil))
	if strings.Contains(rec.Body.String(), "display_names") {
		t.Fatalf("listing for another client: %s", rec.Body)
	}

	// The restriction composes: an entry does not widen the client's list.
	h.SetClientPolicy(func(string) []string { return []string{"github"} })
	rec = httptest.NewRecorder()
	h.HandleRedirect(rec, httptest.NewRequest("GET", "/auth/social?provider=microsoft&session_id="+sess.SessionID, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("outside the list: %d", rec.Code)
	}

	// A broken entry refuses, it never falls back to the platform's registration.
	h.SetClientPolicy(nil)
	h.SetFederation(func(string, string, *Provider) (*Provider, error) { return nil, errors.New("broken") }, nil)
	rec = httptest.NewRecorder()
	h.HandleRedirect(rec, httptest.NewRequest("GET", "/auth/social?provider=microsoft&session_id="+sess.SessionID, nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("broken entry: %d", rec.Code)
	}
}

// Graph says nothing about an address, so Microsoft's platform registration
// proves none; a registration that vouches does, and Google's own claim counts.
func TestEmailVerifiedOnTheCode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/graph":
			json.NewEncoder(w).Encode(map[string]string{"id": "directory-id", "mail": "ada@example.com"})
		case "/google":
			json.NewEncoder(w).Encode(map[string]any{"sub": "g1", "email": "ada@example.com", "email_verified": true})
		}
	}))
	defer upstream.Close()

	for _, c := range []struct {
		name, provider, info string
		vouches, want        bool
	}{
		{"platform registration", "microsoft", "/graph", false, false},
		{"own tenant", "microsoft", "/graph", true, true},
		{"provider's claim", "google", "/google", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			providers := NewProviders()
			providers.Register(&Provider{Name: c.provider, ClientID: "id", ClientSecret: "s", AuthURL: upstream.URL + "/auth",
				TokenURL: upstream.URL + "/token", UserInfoURL: upstream.URL + c.info, VouchesEmail: c.vouches})
			sessions, codes := oidc.NewSessionStore(), oidc.NewCodeStore()
			sessions.Create(&oidc.AuthSession{SessionID: "s1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute)})
			h := NewHandler(providers, codes, sessions, "https://idp.example")
			rec := httptest.NewRecorder()
			h.HandleRedirect(rec, httptest.NewRequest("GET", "/auth/social?provider="+c.provider+"&session_id=s1", nil))
			loc, _ := url.Parse(rec.Header().Get("Location"))
			rec = httptest.NewRecorder()
			h.HandleCallback(rec, httptest.NewRequest("GET", "/auth/social/callback?code=x&state="+loc.Query().Get("state"), nil))
			session, _ := sessions.Get("s1")
			ac, ok := codes.Consume(session.AuthCode)
			if !ok {
				t.Fatalf("no code: %d %s", rec.Code, rec.Body)
			}
			if ac.EmailVerified != c.want {
				t.Fatalf("verified %v, want %v", ac.EmailVerified, c.want)
			}
		})
	}
}
