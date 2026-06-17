// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package attributes

import "testing"

func TestValueSet_Locale(t *testing.T) {
	vs := ValueSet("locale")
	if len(vs) == 0 {
		t.Fatal("locale value set is empty")
	}
	found := false
	for _, v := range vs {
		if v.Value == "en-GB" {
			found = true
		}
		if v.Value == "" || v.Label == "" {
			t.Errorf("value option missing value/label: %+v", v)
		}
	}
	if !found {
		t.Error("expected en-GB in the locale value set")
	}
}

func TestReferentialFile(t *testing.T) {
	if _, ok := ReferentialFile("locale"); !ok {
		t.Error("ReferentialFile(locale) not found")
	}
	if _, ok := ReferentialFile("does-not-exist"); ok {
		t.Error("ReferentialFile(does-not-exist) should not be found")
	}
}

func TestValueSet_Nationality(t *testing.T) {
	vs := ValueSet("nationality")
	if len(vs) < 150 {
		t.Fatalf("nationality value set too small: %d", len(vs))
	}
	want := map[string]bool{"GBR": false, "USA": false, "FRA": false}
	for _, v := range vs {
		if len(v.Value) != 3 {
			t.Errorf("expected ISO 3166-1 alpha-3, got %q", v.Value)
		}
		if _, ok := want[v.Value]; ok {
			want[v.Value] = true
		}
	}
	for code, found := range want {
		if !found {
			t.Errorf("nationality value set missing %q", code)
		}
	}
	// The attribute references the served set.
	if ByKey["nationality"].ValuesURL != "/referential/nationality.json" {
		t.Errorf("nationality valuesUrl = %q", ByKey["nationality"].ValuesURL)
	}
}

func TestNormalizeLocale(t *testing.T) {
	cases := map[string]string{
		"en-GB": "en-GB", // already canonical
		"en_US": "en-US", // underscore + casing handled
		"EN-gb": "en-GB", // casing
		"fr":    "fr",
		"en-NZ": "en",      // region not curated -> base language
		"":      "",        // empty passthrough
		"xx-YY": "xx-YY",   // unknown -> cleaned input
	}
	for in, want := range cases {
		if got := NormalizeLocale(in); got != want {
			t.Errorf("NormalizeLocale(%q) = %q, want %q", in, got, want)
		}
	}
}

// KYC attributes live under the request-gated 'identity' scope and are marked
// identityVerifiable, so they are never pulled by an ordinary 'profile' request.
func TestIdentityScopeAttributes(t *testing.T) {
	for _, key := range []string{"birthdate", "nationality", "age_over_18", "age_over_21"} {
		a, ok := ByKey[key]
		if !ok {
			t.Fatalf("attribute %q missing from referential", key)
		}
		if a.Scope != "identity" {
			t.Errorf("%q scope = %q, want identity", key, a.Scope)
		}
		if !a.IdentityVerifiable {
			t.Errorf("%q should be identityVerifiable", key)
		}
	}
	// given_name/family_name are identityVerifiable but stay under profile.
	for _, key := range []string{"given_name", "family_name"} {
		if !ByKey[key].IdentityVerifiable {
			t.Errorf("%q should be identityVerifiable", key)
		}
		if ByKey[key].Scope != "profile" {
			t.Errorf("%q scope changed unexpectedly", key)
		}
	}
	// The 'identity' scope groups exactly the gov-only KYC claims.
	got := map[string]bool{}
	for _, k := range ByScope["identity"] {
		got[k] = true
	}
	for _, k := range []string{"birthdate", "nationality", "age_over_18", "age_over_21"} {
		if !got[k] {
			t.Errorf("ByScope[identity] missing %q", k)
		}
	}
}

// NormalizeClaims should emit a canonical locale tag.
func TestNormalizeClaims_NormalisesLocale(t *testing.T) {
	attrs, _ := NormalizeClaims("google", map[string]interface{}{
		"sub":    "u1",
		"locale": "en_US",
	})
	if attrs["locale"] != "en-US" {
		t.Errorf("locale = %q, want en-US", attrs["locale"])
	}
}
