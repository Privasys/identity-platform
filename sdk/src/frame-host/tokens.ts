// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Reading the claims of the tokens this frame holds (never verifying
 * them: the identity provider signed them and checks them on use).
 */

/** JSON encoded as base64url (padding optional), or null when it is not. */
export function b64urlJson(s: string): Record<string, unknown> | null {
    try {
        const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
        const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '='));
        const v: unknown = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
        return v && typeof v === 'object' ? v as Record<string, unknown> : null;
    } catch {
        return null;
    }
}

/** The claims of a JWT, unverified (the identity provider signed it and
 *  checks it again on use), or null when unreadable. */
export function jwtPayload(token: string): Record<string, unknown> | null {
    return b64urlJson(token.split('.')[1] ?? '');
}

/** The session id (`sid`) of an access token, or null. */
export function tokenSid(token: string): string | null {
    const sid = jwtPayload(token)?.sid;
    return typeof sid === 'string' && sid ? sid : null;
}

/** Epoch-ms `exp` of a JWT, or null when unreadable. */
export function tokenExpMs(token: string): number | null {
    const exp = jwtPayload(token)?.exp;
    return typeof exp === 'number' ? exp * 1000 : null;
}

/** Whether an access token carries the identity provider's wallet marker. */
export function tokenSaysWallet(token: string): boolean {
    const w = jwtPayload(token)?.wallet;
    return w === true || w === 'true';
}

/** Whether an access token was issued for this audience. */
export function tokenAudienceIs(token: string, audience: string): boolean {
    const aud = jwtPayload(token)?.aud;
    return Array.isArray(aud) ? aud.includes(audience) : aud === audience;
}

/** Check whether an access token's exp claim is within a safety margin. */
export function isTokenExpired(token: string, marginMs = 30_000): boolean {
    const exp = tokenExpMs(token);
    if (exp === null) return false;
    return exp - marginMs < Date.now();
}
