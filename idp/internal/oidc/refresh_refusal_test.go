// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package oidc

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/Privasys/idp/internal/tokens"
)

// A refresh refused for what it asks (another platform's audience, a scope
// the grant does not cover) leaves the sign-in usable: the refresh token is
// spent only when a request is accepted. A token presented by another client
// is still spent.
func TestARefusedRefreshKeepsTheSignIn(t *testing.T) {
	tokens.SetPlatformAudiences([]string{"privasys-platform-test"})
	t.Cleanup(func() { tokens.SetPlatformAudiences(nil) })
	s := signIn(t, "acct-1", "")
	rt := s.tokens["refresh_token"].(string)
	refresh := func(client, scope string) (int, map[string]interface{}) {
		v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {client}}
		if scope != "" {
			v.Set("scope", scope)
		}
		return postForm(t, s.tokenHandler, "/token", v)
	}

	for _, scope := range []string{
		"audience:privasys-platform-test openid", // another platform
		"openid address",                         // not in the grant
	} {
		if c, b := refresh("privasys-cli", scope); c != http.StatusBadRequest || b["error"] != "invalid_scope" {
			t.Fatalf("refresh asking %q: %d %v, want invalid_scope", scope, c, b)
		}
	}
	// The same refresh token still works.
	c, b := refresh("privasys-cli", "")
	if c != http.StatusOK {
		t.Fatalf("refresh after refusals: %d %v", c, b)
	}
	// Rotation: the used token is spent once accepted.
	if c, _ := refresh("privasys-cli", ""); c == http.StatusOK {
		t.Fatal("a refresh token was accepted twice")
	}

	// Another client is refused (an unknown one before the token is read).
	rt = b["refresh_token"].(string)
	if c, _ := refresh("someone-else", ""); c == http.StatusOK {
		t.Fatal("another client's refresh was accepted")
	}
	if c, b := refresh("privasys-cli", ""); c != http.StatusOK {
		t.Fatalf("the sign-in after an unknown client's attempt: %d %v", c, b)
	}
}
