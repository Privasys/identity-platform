// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package oidc

import (
	"testing"

	"github.com/Privasys/idp/internal/tokens"
)

func withTestPlatform(t *testing.T) {
	t.Helper()
	tokens.SetPlatformAudiences([]string{"aud-test", "aud-unlisted"})
	tokens.SetPlatformDomains([]string{"aud-test=test.example.org"})
	t.Cleanup(func() {
		tokens.SetPlatformDomains(nil)
		tokens.SetPlatformAudiences(nil)
	})
}

func TestASignInGetsThePlatformOfItsPage(t *testing.T) {
	withTestPlatform(t)
	cases := []struct {
		scope, origin, want string
		refused             bool
	}{
		// No audience named: the page's platform decides.
		{"openid offline_access", "https://app.test.example.org", "audience:aud-test openid offline_access", false},
		{"openid offline_access", "https://test.example.org/cb?x=1", "audience:aud-test openid offline_access", false},
		{"openid", "https://www.example.org", "openid", false},
		{"openid", "", "openid", false},
		// The page's own platform, named.
		{"audience:aud-test openid", "https://app.test.example.org", "audience:aud-test openid", false},
		{"audience:" + tokens.PlatformAudience + " openid", "https://www.example.org", "audience:" + tokens.PlatformAudience + " openid", false},
		// Another platform's audience: refused, both ways.
		{"audience:" + tokens.PlatformAudience + " openid", "https://app.test.example.org", "", true},
		{"audience:aud-test openid", "https://www.example.org", "", true},
		// An app's or a resource's audience is the page's to ask for.
		{"audience:app:0123 openid", "https://app.test.example.org", "audience:app:0123 openid", false},
		{"audience:attestation-server openid", "https://www.example.org", "audience:attestation-server openid", false},
		// No dot boundary: not the test platform.
		{"openid", "https://nottest.example.org", "openid", false},
	}
	for _, c := range cases {
		got, err := scopeForPlatform(c.scope, c.origin)
		if c.refused {
			if err == nil {
				t.Errorf("scopeForPlatform(%q, %q) = %q, want refused", c.scope, c.origin, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("scopeForPlatform(%q, %q) = %q, %v; want %q", c.scope, c.origin, got, err, c.want)
		}
	}
}

func TestARefreshNeverCrossesToAnotherPlatform(t *testing.T) {
	withTestPlatform(t)
	def := tokens.PlatformAudience
	cases := []struct {
		granted, asked string
		ok             bool
	}{
		{"openid offline_access", "audience:attestation-server openid", true},
		// default -> default, test -> test.
		{"openid offline_access", "audience:" + def + " openid", true},
		{"audience:aud-test openid offline_access", "audience:aud-test openid", true},
		// default -> the one other published platform: TEMPORARY allowance.
		{"openid offline_access", "audience:aud-test openid", true},
		{"audience:" + def + " openid offline_access", "audience:aud-test openid", true},
		// test -> default: never.
		{"audience:aud-test openid offline_access", "audience:" + def + " openid", false},
		// a platform the list does not publish (no domains): never.
		{"openid offline_access", "audience:aud-unlisted openid", false},
		{"audience:aud-test openid offline_access", "audience:aud-unlisted openid", false},
		{"audience:aud-test openid offline_access", "audience:app:0123 openid", true},
		// an app grant mints no platform at all.
		{"audience:app:0123 openid offline_access", "audience:" + def + " openid", false},
		{"audience:app:0123 openid offline_access", "audience:aud-test openid", false},
		{"audience:app:0123 openid offline_access", "openid", true},
	}
	for _, c := range cases {
		if got := refreshStaysOnPlatform(c.granted, c.asked); got != c.ok {
			t.Errorf("refreshStaysOnPlatform(%q, %q) = %t, want %t", c.granted, c.asked, got, c.ok)
		}
	}
}

// With a third platform published, the default reaches neither other one:
// the allowance is for exactly one other platform.
func TestTheAllowanceEndsWithAThirdPlatform(t *testing.T) {
	tokens.SetPlatformAudiences([]string{"aud-test", "aud-third"})
	tokens.SetPlatformDomains([]string{"aud-test=test.example.org", "aud-third=third.example.org"})
	t.Cleanup(func() {
		tokens.SetPlatformDomains(nil)
		tokens.SetPlatformAudiences(nil)
	})
	for _, asked := range []string{"aud-test", "aud-third"} {
		if refreshStaysOnPlatform("openid offline_access", "audience:"+asked+" openid") {
			t.Errorf("with three platforms, the default minted %s", asked)
		}
	}
}

func TestAToolsRefreshNeverMintsForAnotherApp(t *testing.T) {
	const a, b = "audience:app:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "audience:app:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cases := []struct {
		granted, asked string
		ok             bool
	}{
		{a + " openid offline_access", a + " openid", true},
		{a + " openid offline_access", b + " openid", false},
		{"openid offline_access", b + " openid", false},
		{a + " openid offline_access", "audience:attestation-server openid", true},
		{a + " openid offline_access", "openid", true},
	}
	for _, c := range cases {
		if got := refreshStaysOnApp(c.granted, c.asked); got != c.ok {
			t.Errorf("refreshStaysOnApp(%q, %q) = %t, want %t", c.granted, c.asked, got, c.ok)
		}
	}
}

// Only a refresh that crosses platforms through the temporary allowance
// counts as using it: that is the line that says when it can be removed.
func TestOnlyACrossingCountsAsUsingTheAllowance(t *testing.T) {
	withTestPlatform(t)
	def := tokens.PlatformAudience
	for _, c := range []struct {
		granted, asked string
		uses           bool
	}{
		{"openid offline_access", "audience:aud-test openid", true},
		{"audience:" + def + " openid", "audience:aud-test openid", true},
		{"openid offline_access", "audience:" + def + " openid", false},
		{"audience:aud-test openid", "audience:aud-test openid", false},
		{"openid offline_access", "audience:attestation-server openid", false},
		{"openid offline_access", "openid", false},
	} {
		if got := refreshUsesAllowance(c.granted, c.asked); got != c.uses {
			t.Errorf("refreshUsesAllowance(%q, %q) = %t, want %t", c.granted, c.asked, got, c.uses)
		}
	}
}
