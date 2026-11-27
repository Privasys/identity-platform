// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The page's bookkeeping, free of the DOM: a session from what the frame
 * reports, whether a configuration asks for more than a session covers, and
 * how a sealed channel's state and failures read to the page.
 */

import type { AttributeDisclosure, Session } from './types';

/** What the frame reports about the stored session. */
export interface SessionView {
    token: string;
    method: Session['method'];
    requestedAttributes?: string[];
    scope?: string;
}

/** The claims of a JWT, unverified, or null. */
export function claimsOf(token: string): Record<string, unknown> | null {
    try {
        const seg = token.split('.')[1] ?? '';
        const b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
        const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '='));
        const v: unknown = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
        return v && typeof v === 'object' ? v as Record<string, unknown> : null;
    } catch {
        return null;
    }
}

/** A frame report, checked: null when it is not a session. */
export function parseView(raw: unknown): SessionView | null {
    const v = raw as Partial<SessionView> | null | undefined;
    if (!v || typeof v.token !== 'string' || !v.token) return null;
    const method = v.method === 'wallet' || v.method === 'passkey' || v.method === 'social' ? v.method : 'passkey';
    return {
        token: v.token,
        method,
        requestedAttributes: Array.isArray(v.requestedAttributes) ? v.requestedAttributes.map(String) : [],
        scope: typeof v.scope === 'string' ? v.scope : '',
    };
}

/** SD-JWT VC serialisation: a compact JWS followed by `~` (no disclosures). */
const SD_JWT_RE = /^eyJ[\w-]*\.[\w-]+\.[\w-]+~$/;

/**
 * The gov-attribute disclosures in an access token: every claim whose value
 * is an enclave-signed SD-JWT VC. Decoded for display only; the signature is
 * checked against the issuer's JWKS server-side or at audit.
 */
export function extractDisclosures(token: string): AttributeDisclosure[] | undefined {
    const claims = claimsOf(token);
    if (!claims) return undefined;
    const out: AttributeDisclosure[] = [];
    for (const [key, raw] of Object.entries(claims)) {
        if (typeof raw !== 'string' || !SD_JWT_RE.test(raw)) continue;
        const vc = claimsOf(raw.slice(0, -1));
        if (!vc) continue;
        out.push({
            claim: typeof vc.claim === 'string' ? vc.claim : key,
            value: vc.value,
            assurance: typeof vc.assurance === 'string' ? vc.assurance : undefined,
            evidence: vc.evidence && typeof vc.evidence === 'object' ? vc.evidence as Record<string, unknown> : undefined,
            issuer: typeof vc.iss === 'string' ? vc.iss : undefined,
            issuedAt: typeof vc.iat === 'number' ? vc.iat : undefined,
            expiresAt: typeof vc.exp === 'number' ? vc.exp : undefined,
            token: raw,
        });
    }
    return out.length ? out : undefined;
}

/**
 * The session for a token. A renewed token carries no disclosures, so a
 * session renewed from the same sign-in (the same `sid`) keeps those of
 * the one it replaces.
 */
export function sessionOf(view: SessionView, previous: Session | null): Session {
    const claims = claimsOf(view.token);
    const exp = typeof claims?.exp === 'number' ? claims.exp * 1000 : 0;
    const own = extractDisclosures(view.token);
    const sameSignIn = !!previous && !!claims?.sid && claimsOf(previous.token)?.sid === claims.sid;
    const disclosures = own ?? (sameSignIn ? previous!.disclosures : undefined);
    return { token: view.token, method: view.method, expiresAt: exp, ...(disclosures ? { disclosures } : {}) };
}

/**
 * The attribute keys and scope tokens a configuration asks for beyond the
 * request the stored session was minted for, or null when it covers them.
 * The base is the raw request the session recorded, never the granted set:
 * a key the identity provider dropped never appears in a grant, and
 * comparing against the grant would ask again on every connect().
 */
export function widenedBy(
    config: { attributes?: readonly string[]; scope?: readonly string[] },
    view: SessionView,
): string[] | null {
    const prior = new Set(view.requestedAttributes ?? []);
    const widened: string[] = (config.attributes ?? []).filter((k) => !prior.has(k));
    const priorScope = new Set((view.scope ?? '').split(/\s+/).filter(Boolean));
    if (priorScope.size) {
        for (const s of config.scope ?? ['openid', 'offline_access']) {
            if (s !== 'openid' && !priorScope.has(s)) widened.push(s);
        }
    }
    return widened.length ? widened : null;
}

/** A sealed session's liveness, as a channel state. */
export function channelState(status: unknown): 'ok' | 'reconnecting' | 'signed-out' {
    if (status === 'ok') return 'ok';
    if (status === 'recovering') return 'reconnecting';
    return 'signed-out';
}

/**
 * Whether a failed resume can be recovered by one tap in the wallet, and
 * the reason to show: null the first time (no approval yet), or what changed
 * (`enc-changed`, `workload-changed`, `voucher-expired`, ...). Undefined
 * when a wallet approval would not help.
 */
export function approvalReason(error: string, reason?: string): string | null | undefined {
    if (error === 'no-voucher') return null;
    if (error === 'rejected') return reason || 'rejected';
    return undefined;
}

/** An enclave host as the page names it: a DNS name with an optional port, no scheme. */
export function appHost(raw: string): string {
    const host = String(raw ?? '').trim().toLowerCase();
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$/.test(host) || host.length > 253) {
        throw new Error(`AuthFrame: "${raw}" is not a host name (no scheme, no path)`);
    }
    return host;
}

/**
 * A `RequestInit` reduced to what survives `postMessage`: AbortSignal and
 * Headers throw on structured clone, so the signal is dropped (aborts are
 * forwarded as a cancel message) and headers become a plain record.
 */
export function cloneableInit(init?: RequestInit): { headers?: Record<string, string> } | undefined {
    if (!init) return undefined;
    if (!init.headers) return {};
    const h: Record<string, string> = {};
    if (init.headers instanceof Headers) init.headers.forEach((v, k) => { h[k] = v; });
    else if (Array.isArray(init.headers)) for (const [k, v] of init.headers) h[k] = v;
    else Object.assign(h, init.headers as Record<string, string>);
    return { headers: h };
}
