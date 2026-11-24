// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package tokens

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
)

// Platform is one platform a holder's key can be issued for: its audience,
// and the domains whose hosts belong to it. The platform with no domains is
// the default: every host no other platform claims.
type Platform struct {
	Audience string   `json:"audience"`
	Domains  []string `json:"domains,omitempty"`
}

// platformDomains maps an extra platform audience to its domains.
var platformDomains = map[string][]string{}

// SetPlatformDomains records which domains belong to which extra platform,
// from "audience=domain" pairs (an audience may repeat). A pair is ignored
// when its audience is not a platform audience, is the default one, or its
// domain is not a plain host name. Call once at start-up, after
// SetPlatformAudiences.
func SetPlatformDomains(pairs []string) {
	out := map[string][]string{}
	for _, p := range pairs {
		aud, domain, ok := strings.Cut(strings.TrimSpace(p), "=")
		aud = strings.TrimSpace(aud)
		domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
		if !ok || aud == PlatformAudience || !IsPlatformAudience(aud) || !plainHost(domain) {
			continue
		}
		if !slices.Contains(out[aud], domain) {
			out[aud] = append(out[aud], domain)
		}
	}
	platformDomains = out
}

func plainHost(h string) bool {
	if h == "" || !strings.Contains(h, ".") {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// Platforms lists the platforms: the default first, then each extra one that
// has domains, in the order the audiences were set.
func Platforms() []Platform {
	out := []Platform{{Audience: PlatformAudience}}
	for _, aud := range platformAudiences {
		if d := platformDomains[aud]; len(d) > 0 {
			out = append(out, Platform{Audience: aud, Domains: slices.Clone(d)})
		}
	}
	return out
}

// HandlePlatforms serves the platforms, so a wallet can ask for a key for
// the platform a host belongs to without knowing any platform by name. It is
// public: it says nothing about any holder.
//
//	GET /wallet/platforms -> 200 {"platforms":[{"audience","domains"}]}
func HandlePlatforms(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(map[string]any{"platforms": Platforms()})
}
