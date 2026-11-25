// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Which platform a page belongs to, from the identity provider's published
// platform list (GET /wallet/platforms). A page's platform is the one listing
// its host, or the longest domain its host ends in at a dot, else the
// default: the one platform that lists no domain. The wallet places a host
// the same way.

import type { PlatformScope } from './session';

export type PlatformEntry = { audience: string; domains: string[] };

/** A platform list as served, or null when it is not one: exactly one
 *  platform without domains (the default), every name and domain plain. */
export function parsePlatforms(body: unknown): PlatformEntry[] | null {
    const raw = (body as { platforms?: unknown } | null)?.platforms;
    if (!Array.isArray(raw) || raw.length > 64) return null;
    const out: PlatformEntry[] = [];
    for (const p of raw) {
        const audience = (p as { audience?: unknown } | null)?.audience;
        const domains = (p as { domains?: unknown } | null)?.domains ?? [];
        if (typeof audience !== 'string' || !/^[A-Za-z0-9._:-]{1,253}$/.test(audience) || !Array.isArray(domains)) return null;
        const clean: string[] = [];
        for (const d of domains) {
            if (typeof d !== 'string' || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) return null;
            clean.push(d);
        }
        out.push({ audience, domains: clean });
    }
    return out.filter((p) => p.domains.length === 0).length === 1 ? out : null;
}

/** The platform of the page at `origin`, from a parsed platform list, or
 *  null when `origin` is not a URL. */
export function platformScopeOf(list: PlatformEntry[], origin: string): PlatformScope | null {
    let host: string;
    try {
        host = new URL(origin).hostname.toLowerCase().replace(/\.$/, '');
    } catch {
        return null;
    }
    if (!host) return null;
    const defaultPlatform = list.find((p) => p.domains.length === 0)!.audience;
    let platform = defaultPlatform;
    let best = 0;
    for (const p of list) {
        for (const d of p.domains) {
            if ((host === d || host.endsWith(`.${d}`)) && d.length > best) {
                platform = p.audience;
                best = d.length;
            }
        }
    }
    return { platform, defaultPlatform, platforms: list.map((p) => p.audience) };
}
