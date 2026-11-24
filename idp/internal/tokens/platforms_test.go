// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package tokens

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestPlatformsListTheDefaultThenEachWithDomains(t *testing.T) {
	defer SetPlatformAudiences(nil)
	defer SetPlatformDomains(nil)
	SetPlatformAudiences([]string{"privasys-platform-test", "privasys-platform-other"})
	SetPlatformDomains([]string{
		" privasys-platform-test = .Test.Privasys.org ",
		"privasys-platform-test=test.privasys.org",
		"privasys-platform=privasys.org", // the default claims no domain
		"unknown=example.org",            // not a platform audience
		"privasys-platform-test=bad host",
		"privasys-platform-test=localhost",
		"no-equals",
	})
	want := []Platform{
		{Audience: "privasys-platform"},
		{Audience: "privasys-platform-test", Domains: []string{"test.privasys.org"}},
	}
	if got := Platforms(); !reflect.DeepEqual(got, want) {
		t.Fatalf("platforms: %+v", got)
	}

	rec := httptest.NewRecorder()
	HandlePlatforms(rec, httptest.NewRequest("GET", "/wallet/platforms", nil))
	var body struct {
		Platforms []Platform `json:"platforms"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || !reflect.DeepEqual(body.Platforms, want) {
		t.Fatalf("served: %s (%v)", rec.Body.String(), err)
	}
}

func TestPlatformsWithNothingSetIsTheDefaultOnly(t *testing.T) {
	SetPlatformDomains(nil)
	if got := Platforms(); len(got) != 1 || got[0].Audience != PlatformAudience || got[0].Domains != nil {
		t.Fatalf("platforms: %+v", got)
	}
}
