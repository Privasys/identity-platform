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

// DefaultMayMintOther says whether a refresh of a grant made on the default
// platform may mint `asked`: only when the published list has exactly one
// other platform and `asked` is it. Never the other way, never a platform
// the list does not publish, and with a third platform listed, never at all.
//
// TEMPORARY: the CLI holds one sign-in, made on the default platform, and
// mints the other platform's token by refresh. A default-platform sign-in
// minting a token the default platform does not accept gives that other
// platform nothing usable against the default one. Remove once the CLI holds
// one sign-in per platform.
func DefaultMayMintOther(granted, asked string) bool {
	if granted != PlatformAudience || asked == PlatformAudience {
		return false
	}
	var others []string
	for _, p := range Platforms() {
		if p.Audience != PlatformAudience {
			others = append(others, p.Audience)
		}
	}
	return len(others) == 1 && others[0] == asked
}

// PlatformOfHost names the platform a host belongs to: the platform listing
// the host itself or the longest domain the host ends in at a dot, else the
// default. The wallet matches the same way on the list HandlePlatforms serves.
func PlatformOfHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	best, bestLen := PlatformAudience, 0
	if host == "" {
		return best
	}
	for _, p := range Platforms() {
		for _, d := range p.Domains {
			if (host == d || strings.HasSuffix(host, "."+d)) && len(d) > bestLen {
				best, bestLen = p.Audience, len(d)
			}
		}
	}
	return best
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
