// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Which platform a host belongs to, so a key sent there is one only that
 * platform accepts.
 *
 * The wallet knows no platform by name. privasys.id, which issues the keys,
 * publishes the platforms: each one's audience and the domains whose hosts are
 * its own. A host no platform claims gets the default audience. A new platform
 * is a change at privasys.id, never a wallet release.
 *
 * The list is read once per launch and kept for the launches when privasys.id
 * cannot be reached. A wallet that has never read it sends no key to a named
 * host: it cannot tell which platform the host is, and a key for the wrong one
 * must not leave the device.
 */

import * as SecureStore from '@/utils/storage';

const IDP_BASE_URL = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** The audience of every host no platform claims, privasys.id included. */
export const DEFAULT_AUDIENCE = process.env['EXPO_PUBLIC_PLATFORM_AUDIENCE'] || 'privasys-platform';

const STORE_KEY = 'privasys.platforms';
const AUDIENCE = /^[A-Za-z0-9._:-]{1,128}$/;
const DOMAIN = /^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$/;

/** A platform that claims domains (the default one claims none). */
interface Platform {
    audience: string;
    domains: string[];
}

function parse(body: unknown): Platform[] | null {
    const list = (body as { platforms?: unknown } | null)?.platforms;
    if (!Array.isArray(list)) return null;
    const out: Platform[] = [];
    for (const p of list) {
        const audience = (p as { audience?: unknown })?.audience;
        const domains = (p as { domains?: unknown })?.domains;
        if (typeof audience !== 'string' || !AUDIENCE.test(audience)) return null;
        if (domains === undefined || domains === null) continue;
        if (!Array.isArray(domains) || domains.some((d) => typeof d !== 'string' || !DOMAIN.test(d))) return null;
        if (audience !== DEFAULT_AUDIENCE && domains.length > 0) out.push({ audience, domains: domains as string[] });
    }
    return out;
}

let loaded: Promise<Platform[]> | null = null;

async function load(): Promise<Platform[]> {
    try {
        const res = await fetch(`${IDP_BASE_URL}/wallet/platforms`, { headers: { Accept: 'application/json' } });
        if (!res.ok) throw new Error(`platforms (${res.status})`);
        const fresh = parse(await res.json());
        if (!fresh) throw new Error('platforms: not a platform list');
        await SecureStore.setItemAsync(STORE_KEY, JSON.stringify({ platforms: fresh })).catch(() => {});
        return fresh;
    } catch (e) {
        const kept = await SecureStore.getItemAsync(STORE_KEY).catch(() => null);
        const platforms = kept ? parse(JSON.parse(kept)) : null;
        if (platforms) return platforms;
        throw e;
    }
}

function platforms(): Promise<Platform[]> {
    if (!loaded) {
        loaded = load().catch((e) => {
            loaded = null;
            throw e;
        });
    }
    return loaded;
}

function hostOf(target: string): string {
    let host = target;
    try {
        if (target.includes('://')) host = new URL(target).hostname;
    } catch {
        /* a bare host */
    }
    return host.split('/')[0].split(':')[0].toLowerCase().replace(/\.$/, '');
}

/**
 * The audience for a call to `target` (a URL or a bare host): that of the
 * platform claiming the host, the most specific domain winning, or the default.
 * Throws when the platforms have never been read.
 */
export async function audienceFor(target: string): Promise<string> {
    const host = hostOf(target);
    let best: { audience: string; length: number } | null = null;
    for (const p of await platforms()) {
        for (const d of p.domains) {
            if ((host === d || host.endsWith(`.${d}`)) && (!best || d.length > best.length)) {
                best = { audience: p.audience, length: d.length };
            }
        }
    }
    return best?.audience ?? DEFAULT_AUDIENCE;
}

/** Every audience a key may be cached under: for clearing them all. */
export async function knownAudiences(): Promise<string[]> {
    const extra = await platforms().then(
        (list) => list.map((p) => p.audience),
        () => [] as string[],
    );
    return [...new Set([DEFAULT_AUDIENCE, ...extra])];
}

/** Read the platforms again on the next call (tests, and a new launch). */
export function forgetPlatforms(): void {
    loaded = null;
}
