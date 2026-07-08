// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Sessions API client — calls the IdP unified-sessions endpoints.
 *
 * Backed by `internal/sessions` in the IdP. Each session is one row in
 * the `(user, app, device)` table and is the JWT-revocation handle the
 * user controls from the wallet.
 *
 * Auth: short-lived wallet session token (`Bearer wallet:<token>`),
 * issued by the wallet's FIDO2 register/authenticate flow against
 * privasys.id and refreshed on biometric unlock.
 */

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** A row in the IdP `sessions` table. */
export interface IdpSession {
    /** Stable session id (32-byte base64url). Token revocation handle. */
    sid: string;
    /** OIDC client_id this session was issued to. */
    client_id: string;
    /** Device identifier (currently empty; populated once the SDK
     *  surfaces a device hint). */
    device_id: string;
    /** Unix seconds. */
    created_at: number;
    /** Unix seconds. */
    last_seen_at: number;
    /** Unix seconds. */
    expires_at: number;
}

interface ListSessionsResponse {
    sessions: IdpSession[];
}

function walletAuth(walletSessionToken: string): HeadersInit {
    return { Authorization: `Bearer wallet:${walletSessionToken}` };
}

async function idpFetch<T>(path: string, init: RequestInit): Promise<T> {
    const res = await fetch(`${IDP_BASE}${path}`, {
        ...init,
        headers: {
            'Content-Type': 'application/json',
            ...init.headers,
        },
    });
    if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(body.error || `Request failed: ${res.status}`);
    }
    if (res.status === 204) return undefined as T;
    return res.json() as Promise<T>;
}

/** List the current user's active sessions, most-recently-active first. */
export async function listMySessions(walletSessionToken: string): Promise<IdpSession[]> {
    const body = await idpFetch<ListSessionsResponse>('/sessions/me', {
        method: 'GET',
        headers: walletAuth(walletSessionToken),
    });
    return body.sessions ?? [];
}

/** Revoke a specific session id. Idempotent: 404 on already-revoked sids
 *  is converted into a successful no-op so callers can revoke optimistically. */
export async function revokeSession(walletSessionToken: string, sid: string): Promise<void> {
    try {
        await idpFetch(`/sessions/${encodeURIComponent(sid)}/revoke`, {
            method: 'POST',
            headers: walletAuth(walletSessionToken),
        });
    } catch (err) {
        const msg = (err as Error).message ?? '';
        if (msg.includes('not found')) return;
        throw err;
    }
}
