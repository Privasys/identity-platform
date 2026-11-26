// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package attributes

import (
	"encoding/json"
	"testing"
)

func labelOf(t *testing.T, body []byte, value string) string {
	t.Helper()
	var doc struct {
		Values []ValueOption `json:"values"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, v := range doc.Values {
		if v.Value == value {
			return v.Label
		}
	}
	t.Fatalf("no value %q", value)
	return ""
}

func TestReferentialFileLang(t *testing.T) {
	cases := []struct{ name, lang, value, want string }{
		{"nationality", "fr", "DEU", "Allemagne"},
		{"nationality", "FR", "DEU", "Allemagne"},
		// A regional tag falls back to its language.
		{"country", "de-AT", "FR", "Frankreich"},
		// No copy in that language, or no language: the English base file.
		{"nationality", "ja", "DEU", "Germany"},
		{"nationality", "", "DEU", "Germany"},
		// A malformed tag never reaches the file system.
		{"nationality", "../fr", "DEU", "Germany"},
		{"locale", "fr", "en-GB", "anglais britannique"},
	}
	for _, c := range cases {
		body, ok := ReferentialFileLang(c.name, c.lang)
		if !ok {
			t.Fatalf("%s?lang=%s: not found", c.name, c.lang)
		}
		if got := labelOf(t, body, c.value); got != c.want {
			t.Errorf("%s?lang=%s %s = %q, want %q", c.name, c.lang, c.value, got, c.want)
		}
	}
	if _, ok := ReferentialFileLang("../canonical-attributes", "fr"); ok {
		t.Error("a path in the name must not resolve")
	}
}

// Every per-language copy carries exactly the base file's codes: a holder's
// pick in one language is the same stored value in every other.
func TestReferentialLangSameValues(t *testing.T) {
	for _, name := range []string{"nationality", "country", "locale"} {
		base, _ := ReferentialFile(name)
		want := map[string]bool{}
		for _, v := range ValueSet(name) {
			want[v.Value] = true
		}
		if len(want) == 0 {
			t.Fatalf("%s: empty base (%d bytes)", name, len(base))
		}
		entries, err := referentialFS.ReadDir("referential/i18n/" + name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, e := range entries {
			b, _ := referentialFS.ReadFile("referential/i18n/" + name + "/" + e.Name())
			var doc struct {
				Values []ValueOption `json:"values"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatalf("%s/%s: %v", name, e.Name(), err)
			}
			if len(doc.Values) != len(want) {
				t.Errorf("%s/%s: %d values, base has %d", name, e.Name(), len(doc.Values), len(want))
			}
			for _, v := range doc.Values {
				if !want[v.Value] || v.Label == "" {
					t.Errorf("%s/%s: unexpected %q (%q)", name, e.Name(), v.Value, v.Label)
				}
			}
		}
	}
}
