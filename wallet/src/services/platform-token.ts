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
import { authenticate as fido2Authenticate } from './fido2';
import { ensurePrivasysSession } from './privasys-id';
import { useAuthStore } from '@/stores/auth';

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
    /** credentialId of the identity the token was minted under — a cached
     *  token is only valid while the wallet's active platform identity is
     *  still that credential (see activePlatformCredentialId). */
    mintedBy?: string;
}

let inflight: Promise<string> | null = null;

/**
 * The credential of the wallet's ACTIVE platform identity — the same
 * newest-wins privasys.id credential the sign-in ceremonies assert
 * (connect.tsx via getCredentialForRp), so the Drive the wallet opens is
 * the SAME drive the user sees after a web sign-in. Only a device with no
 * platform credential at all falls back to the canonical slot account.
 * (Minting on the canonical slot unconditionally is how the Drive tab
 * ended up on a different — empty — tenant than drive.privasys.org.)
 */
function activePlatformCredentialId(): string {
    const store = useAuthStore.getState();
    return (
        store.getCredentialForRp('privasys.id')?.credentialId ??
        store.privasysId?.credentialId ??
        ''
    );
}

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
        if (
            s.audience === audience &&
            s.token &&
            s.expiresAt - REFRESH_SKEW_MS > Date.now() &&
            s.mintedBy === activePlatformCredentialId()
        ) {
            return s.token;
        }
        return null;
    } catch {
        return null;
    }
}

async function mint(audience: string): Promise<string> {
    const sessionToken = await platformSessionToken();
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
        audience,
        mintedBy: activePlatformCredentialId()
    };
    await SecureStore.setItemAsync(STORE_KEY, JSON.stringify(stored)).catch(() => {});
    return body.token;
}

/**
 * A `wallet:<token>` session for the active platform identity: authenticate
 * with the same newest-wins privasys.id credential the ceremonies use, so the
 * minted at+jwt carries the sub the user's web sessions (and therefore their
 * Drive tenant) ride. Falls back to the canonical slot session when the
 * device has no platform credential.
 */
async function platformSessionToken(): Promise<string> {
    const cred = useAuthStore.getState().getCredentialForRp('privasys.id');
    if (!cred) {
        return (await ensurePrivasysSession()).sessionToken;
    }
    const result = await fido2Authenticate(
        'privasys.id',
        cred.keyAlias,
        cred.credentialId,
        '', // no browser session relay
        cred.serverRpId ?? 'privasys.id'
    );
    if (!result.sessionToken) {
        throw new Error('No sessionToken from platform authenticate');
    }
    return result.sessionToken;
}
