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
