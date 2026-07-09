// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"testing"

	"github.com/Privasys/idp/internal/clients"
)

// SD-JWT VC serialisations (JWS + '~'); signature irrelevant — acrForCode
// only decodes the (unverified) payload. Payload segments are base64url of:
//   fakeDisclosure:        {"value":true}
//   fakeDisclosureFalse:   {"value":false}                 (a factual "no")
//   fakeFailureReceipt:    {"value":false,"failure":{"retryable":true}}
const fakeDisclosure = "eyJhbGciOiJFUzI1NiJ9.eyJ2YWx1ZSI6dHJ1ZX0.c2ln~"
const fakeDisclosureFalse = "eyJhbGciOiJFUzI1NiJ9.eyJ2YWx1ZSI6ZmFsc2V9.c2ln~"
const fakeFailureReceipt = "eyJhbGciOiJFUzI1NiJ9.eyJ2YWx1ZSI6ZmFsc2UsImZhaWx1cmUiOnsicmV0cnlhYmxlIjp0cnVlfX0.c2ln~"

func TestLooksLikeDisclosureToken(t *testing.T) {
	if !looksLikeDisclosureToken(fakeDisclosure) {
		t.Error("valid SD-JWT shape should classify as disclosure")
	}
	for _, raw := range []string{"", "1990-01-01", "GBR", "true", "eyJ-not-a-jws~", "eyJhbGciOiJFUzI1NiJ9.eyJ4IjoxfQ.c2ln"} {
		if looksLikeDisclosureToken(raw) {
			t.Errorf("%q should NOT classify as disclosure", raw)
		}
	}
}

// TestACRForCode pins the achieved-acr computation: gov-fresh ONLY when at
// least one gov-assured attribute arrived as an enclave-signed disclosure
// token and none arrived raw — everything else is the interactive baseline.
func TestACRForCode(t *testing.T) {
	cli := &clients.Client{}

	cases := []struct {
		name  string
		scope string
		attrs map[string]string
		want  string
	}{
		{"no identity scope", "openid email", map[string]string{"email": "a@b.c"}, "wallet"},
		{"identity scope, nothing disclosed", "openid identity", map[string]string{}, "wallet"},
		{"gov attr as disclosure token", "openid identity",
			map[string]string{"age_over_18": fakeDisclosure}, "gov-fresh"},
		{"gov attr arrived raw", "openid identity",
			map[string]string{"age_over_18": "true"}, "wallet"},
		{"mixed token + raw downgrades", "openid identity",
			map[string]string{"age_over_18": fakeDisclosure, "nationality": "GBR"}, "wallet"},
		{"two disclosure tokens", "openid identity",
			map[string]string{"age_over_18": fakeDisclosure, "nationality": fakeDisclosure}, "gov-fresh"},
		{"presence disclosure tops the ladder", "openid identity",
			map[string]string{"age_over_18": fakeDisclosure, "holder_present": fakeDisclosure}, "gov-presence"},
		{"presence alone", "openid identity",
			map[string]string{"holder_present": fakeDisclosure}, "gov-presence"},
		{"raw presence never counts", "openid identity",
			map[string]string{"holder_present": "true"}, "wallet"},
		{"presence + raw gov downgrades", "openid identity",
			map[string]string{"holder_present": fakeDisclosure, "nationality": "GBR"}, "wallet"},
		// v0.6.0 charged failure receipts must NOT lift the tier.
		{"FAILED presence + real gov disclosures = gov-fresh, NOT gov-presence", "openid identity",
			map[string]string{"age_over_18": fakeDisclosure, "nationality": fakeDisclosure,
				"holder_present": fakeFailureReceipt}, "gov-fresh"},
		{"failed presence alone = wallet", "openid identity",
			map[string]string{"holder_present": fakeFailureReceipt}, "wallet"},
		{"factual age_over_18:false still counts as gov-fresh", "openid identity",
			map[string]string{"age_over_18": fakeDisclosureFalse}, "gov-fresh"},
		{"a failed gov disclosure does not count", "openid identity",
			map[string]string{"age_over_18": fakeFailureReceipt}, "wallet"},
	}
	for _, c := range cases {
		ac := &AuthCode{Scope: c.scope, Attributes: c.attrs}
		if got := acrForCode(ac, cli); got != c.want {
			t.Errorf("%s: acr = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestACRSupported(t *testing.T) {
	for _, v := range []string{"wallet", "gov-fresh", "gov-presence"} {
		if !acrSupported(v) {
			t.Errorf("%s should be supported", v)
		}
	}
	for _, v := range []string{"urn:whatever", ""} {
		if acrSupported(v) {
			t.Errorf("%q should NOT be supported", v)
		}
	}
}

// TestPresenceTokenFilter pins that holder_present survives scope filtering
// ONLY as a disclosure token under the identity scope — a raw value or a
// non-identity scope must drop it.
func TestPresenceTokenFilter(t *testing.T) {
	got := filterAttributesByScope(map[string]string{"holder_present": fakeDisclosure}, "openid identity")
	if got["holder_present"] != fakeDisclosure {
		t.Error("presence disclosure should pass under identity scope")
	}
	if filterAttributesByScope(map[string]string{"holder_present": "true"}, "openid identity") != nil {
		t.Error("raw presence value must be dropped")
	}
	if filterAttributesByScope(map[string]string{"holder_present": fakeDisclosure}, "openid email") != nil {
		t.Error("presence must be dropped without the identity scope")
	}
}
