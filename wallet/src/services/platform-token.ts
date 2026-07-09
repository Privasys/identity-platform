// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Platform access token (`at+jwt`) — the wallet's bearer for control-plane +
 * confidential-app APIs that verify a real OIDC JWT (not the opaque
 * `wallet:<token>` session), e.g. the management service's data-keys/grant and
 * the Drive enclave.
 *
 * Minted via the IdP's API-key flow (the confidential-ai "API key" pattern):
 * POST /api-keys with the wallet session bearer returns a long-lived,
 * session-revocable `at+jwt` bound to the user's identity. Cached + re-minted
 * before expiry. Distinct from services/wia.ts (device attestation) and the
 * `wallet:<token>` FIDO2 session.
 */

import * as SecureStore from '@/utils/storage';
import { ensurePrivasysSession } from './privasys-id';

const IDP_BASE_URL = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** Audience the platform token is minted for. The Drive enclave + mgmt verify
 *  it; override per deployment if a narrower audience is required. */
const PLATFORM_AUDIENCE = process.env['EXPO_PUBLIC_PLATFORM_AUDIENCE'] || 'privasys-platform';

const STORE_KEY = 'privasys.platform-token';
/** Re-mint this long before expiry so a call never rides an about-to-die token. */
const REFRESH_SKEW_MS = 24 * 60 * 60 * 1000; // 1 day

interface StoredToken {
    token: string;
    expiresAt: number; // unix ms
    audience: string;
}

let inflight: Promise<string> | null = null;

/**
 * A valid platform `at+jwt`. Returns a cached one when unexpired; otherwise
 * mints a fresh one via the IdP (which may require a wallet sign-in, i.e. a
 * biometric — so call this from a user-initiated flow, not cold start).
 */
export async function getPlatformToken(audience = PLATFORM_AUDIENCE): Promise<string> {
    const cached = await readCached(audience);
    if (cached) return cached;
    if (inflight) return inflight;
    inflight = mint(audience).finally(() => {
        inflight = null;
    });
    return inflight;
}

/** Drop the cached platform token (e.g. on sign-out). */
export async function clearPlatformToken(): Promise<void> {
    try {
        await SecureStore.deleteItemAsync(STORE_KEY);
    } catch {
        /* ignore */
    }
}

async function readCached(audience: string): Promise<string | null> {
    try {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return null;
        const s = JSON.parse(raw) as StoredToken;
        if (s.audience === audience && s.token && s.expiresAt - REFRESH_SKEW_MS > Date.now()) {
            return s.token;
        }
        return null;
    } catch {
        return null;
    }
}

async function mint(audience: string): Promise<string> {
    const { sessionToken } = await ensurePrivasysSession();
    const res = await fetch(`${IDP_BASE_URL}/api-keys`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer wallet:${sessionToken}`
        },
        body: JSON.stringify({ label: 'Privasys Wallet', audience })
    });
    if (!res.ok) {
        throw new Error(`mint platform token failed (${res.status}): ${(await res.text()).slice(0, 200)}`);
    }
    const body = (await res.json()) as { token: string; expires_at: number };
    if (!body.token) throw new Error('mint platform token: no token in response');
    const stored: StoredToken = {
        token: body.token,
        expiresAt: (body.expires_at ?? Math.floor(Date.now() / 1000) + 3600) * 1000,
        audience
    };
    await SecureStore.setItemAsync(STORE_KEY, JSON.stringify(stored)).catch(() => {});
    return body.token;
}
