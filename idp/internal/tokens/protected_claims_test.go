// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package tokens

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An attribute never writes a claim a verifier or a runtime relies on; only
// what the identity provider asserts does.
func TestAnAttributeNeverWritesAProtectedClaim(t *testing.T) {
	iss, err := NewIssuer(filepath.Join(t.TempDir(), "k.pem"), "https://privasys.id")
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]string{"email": "a@example.org"}
	for k := range protectedClaims {
		attrs[k] = "from-an-attribute"
	}
	tok, err := iss.IssueAccessTokenAsserted("sub-1", "app:x", "sid-1", nil, attrs, Asserted{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c := payload(t, tok)
	for k := range protectedClaims {
		if c[k] == "from-an-attribute" {
			t.Errorf("an attribute wrote %q", k)
		}
	}
	if c["sub"] != "sub-1" || c["aud"] != "app:x" || c["sid"] != "sid-1" || c["typ"] != "at+jwt" || c["email"] != "a@example.org" {
		t.Fatalf("claims: %v", c)
	}
	for _, k := range []string{"azp", ClaimActor, ClaimPrivasysAccount, "nonce", "amr", "acr", "cnf", "jti", "vault_op", "auth_time"} {
		if _, has := c[k]; has {
			t.Errorf("%q present with nothing asserting it", k)
		}
	}

	tok, err = iss.IssueAccessTokenAsserted("sub-1", "app:x", "", nil, attrs,
		Asserted{AuthorizedParty: "tool", Actor: "tool", Account: "acct-1"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c = payload(t, tok)
	act, _ := c[ClaimActor].(map[string]interface{})
	if c["azp"] != "tool" || act == nil || act["client_id"] != "tool" || len(act) != 1 || c[ClaimPrivasysAccount] != "acct-1" {
		t.Fatalf("asserted claims: azp %v act %v account %v", c["azp"], c[ClaimActor], c[ClaimPrivasysAccount])
	}
}

func payload(t *testing.T, jwt string) map[string]interface{} {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]interface{}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
