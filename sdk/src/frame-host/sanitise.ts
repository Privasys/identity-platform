// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Sanitisers for what the embedding page sends: it is rendered and acted
 * on inside this trusted origin, so every value is schema-checked.
 */

import type { AuthUIConfig } from '../ui';

// ── Adopter-config sanitisers ────────────────────────────────────────────
//
// `pitch` and `methods` arrive from the adopter page via postMessage and
// are rendered inside this trusted origin, so they are strictly schema-
// checked: plain strings only (AuthUI renders them as text nodes), capped
// lengths, and a closed method vocabulary.

export function sanitisePitch(raw: unknown): AuthUIConfig['pitch'] {
    if (!raw || typeof raw !== 'object') return undefined;
    const r = raw as Record<string, unknown>;
    const str = (v: unknown, max: number): string | undefined =>
        typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : undefined;
    const bullets = Array.isArray(r.bullets)
        ? r.bullets
            .map((b) => str(b, 200))
            .filter((b): b is string => !!b)
            .slice(0, 5)
        : undefined;
    const logoUrl = str(r.logoUrl, 300);
    const pitch = {
        title: str(r.title, 120),
        description: str(r.description, 600),
        bullets: bullets?.length ? bullets : undefined,
        // Consumer logo: https URLs only (rendered as a plain <img>).
        logoUrl: logoUrl?.startsWith('https://') ? logoUrl : undefined,
    };
    return (pitch.title || pitch.description || pitch.bullets || pitch.logoUrl) ? pitch : undefined;
}

export function sanitiseApp(raw: unknown): AuthUIConfig['app'] {
    if (!raw || typeof raw !== 'object') return undefined;
    const r = raw as Record<string, unknown>;
    const logoUrl = typeof r.logoUrl === 'string' && r.logoUrl.startsWith('https://')
        ? r.logoUrl.slice(0, 300)
        : undefined;
    const displayName = typeof r.displayName === 'string' && r.displayName.trim()
        ? r.displayName.trim().slice(0, 60)
        : undefined;
    return (logoUrl || displayName) ? { logoUrl, displayName } : undefined;
}

export const KNOWN_METHODS = ['wallet', 'passkey', 'social'] as const;
export type KnownMethod = (typeof KNOWN_METHODS)[number];
/** The page's nonce for a link: what its server will look for in the ID token. */
export function sanitiseLinkNonce(raw: unknown): string | undefined {
    const nonce = (raw as { nonce?: unknown } | null | undefined)?.nonce;
    if (typeof nonce !== 'string') return undefined;
    return /^[A-Za-z0-9._~-]{16,256}$/.test(nonce) ? nonce : undefined;
}

/** The user code of a device request: eight letters or digits, however typed. */
export function sanitiseDeviceUserCode(raw: unknown): string | undefined {
    const code = (raw as { userCode?: unknown } | null | undefined)?.userCode;
    if (typeof code !== 'string') return undefined;
    const c = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
    return c.length === 8 ? c : undefined;
}

/** The audience of the first access token: a resource name or `app:<app id>`. */
export function sanitiseAudience(raw: unknown): string | undefined {
    if (typeof raw !== 'string') return undefined;
    return /^[A-Za-z0-9._:-]{1,253}$/.test(raw) ? raw : undefined;
}

// The adopter's list is an order as well as a filter (gate.ts), so it is
// kept as given, less anything unknown or repeated.
export function sanitiseMethods(raw: unknown): AuthUIConfig['methods'] {
    if (!Array.isArray(raw)) return undefined;
    const out: KnownMethod[] = [];
    for (const m of raw) {
        if ((KNOWN_METHODS as readonly unknown[]).includes(m) && !out.includes(m as KnownMethod)) out.push(m as KnownMethod);
    }
    return out.length ? out : undefined;
}

// `providers` narrows the social list to a closed vocabulary; see providers.ts.

export function sanitisePresentation(raw: unknown): AuthUIConfig['presentation'] {
    return raw === 'inline' || raw === 'page' || raw === 'modal' ? raw : undefined;
}

/** The adopter's spend hint, reduced to a non-negative integer cap. */
export function sanitiseSpend(v: unknown): { cap?: number } {
    if (!v || typeof v !== 'object') return {};
    const cap = (v as { cap?: unknown }).cap;
    if (typeof cap === 'number' && Number.isFinite(cap) && cap >= 0) {
        return { cap: Math.floor(cap) };
    }
    return {};
}
