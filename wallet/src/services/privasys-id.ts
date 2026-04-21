// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Privasys ID — the user's canonical identity at privasys.id.
 *
 * The user's identity at privasys.id IS their **Canonical DID**:
 *   `did:web:privasys.id:users:<userId>`
 * where `userId` is derived deterministically from the wallet's pairwise
 * seed (`SHA-256(seed || "privasys-canonical-v1")[0..32]`, see
 * `services/did.ts:generateCanonicalDid`).
 *
 * This service ensures the wallet has a FIDO2 credential registered against
 * the `privasys.id` RP itself with `userHandle = canonicalUserId`. Because
 * the IdP keys its `users` table on `userHandle`, EVERY device the user
 * registers shares the SAME server-side `user_id`. Recovery phrases,
 * guardians and registered devices are all anchored on the canonical
 * identity — not on a per-device account.
 *
 * The session token returned by FIDO2 register/authenticate (format
 * `Bearer wallet:<token>`) is what the wallet uses to call the recovery
 * management endpoints.
 *
 * Forward-looking: the canonical DID is the natural `sub` for W3C
 * Verifiable Credentials issued via OpenID4VCI / SD-JWT. Any VC the user
 * holds binds to the same identity that the recovery phrase protects.
 */

import * as Crypto from 'expo-crypto';

import { register as fido2Register, authenticate as fido2Authenticate } from './fido2';
import { useAuthStore, type PrivasysIdAccount } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';

const PRIVASYS_ORIGIN = 'privasys.id';
const PRIVASYS_KEY_ALIAS = 'privasys-id-account';
const SESSION_TTL_MS = 25 * 60 * 1000; // 25 min (server is 30, leave margin)

/**
 * Derive the canonical user_id from the pairwise seed.
 * Matches `generateCanonicalDid()` in `services/did.ts`.
 */
async function deriveCanonicalUserId(pairwiseSeed: string): Promise<string> {
    const hash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        `${pairwiseSeed}\x00privasys-canonical-v1`,
    );
    return hash.substring(0, 32);
}

/** base64url encoding (no padding). */
function b64url(s: string): string {
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Ensure we have a fresh wallet sessionToken for the user's privasys.id
 * canonical identity. Registers on first call (anchored on the canonical
 * userId from the pairwise seed), re-authenticates afterwards.
 *
 * Both register and authenticate require biometric user verification.
 *
 * @returns the sessionToken to use as `Bearer wallet:<token>` plus the
 *          canonical userId and (first registration only) the BIP39
 *          recovery phrase.
 */
export async function ensurePrivasysSession(displayName?: string): Promise<{ sessionToken: string; userId: string; recoveryPhrase?: string }> {
    const store = useAuthStore.getState();
    const existing = store.privasysId;

    // Cached session still valid?
    if (existing && existing.sessionToken && Date.now() < existing.sessionExpiresAt) {
        return { sessionToken: existing.sessionToken, userId: existing.userId };
    }

    if (existing) {
        const result = await fido2Authenticate(
            PRIVASYS_ORIGIN,
            existing.keyAlias,
            existing.credentialId,
            '', // no browser session relay
            PRIVASYS_ORIGIN,
        );
        if (!result.sessionToken) throw new Error('No sessionToken from authenticate');
        store.setPrivasysSession(result.sessionToken, SESSION_TTL_MS);
        return { sessionToken: result.sessionToken, userId: existing.userId };
    }

    // First-time registration — bind the FIDO2 credential to the canonical
    // userId derived from the pairwise seed. All devices for the same user
    // share this userHandle, so the IdP sees a single `user_id`.
    const profile = useProfileStore.getState().profile;
    if (!profile?.pairwiseSeed) {
        throw new Error('Cannot sign in to Privasys ID: profile not initialised');
    }
    const canonicalUserId = await deriveCanonicalUserId(profile.pairwiseSeed);
    const userHandle = b64url(canonicalUserId);

    const result = await fido2Register(
        PRIVASYS_ORIGIN,
        PRIVASYS_KEY_ALIAS,
        '', // no browser session relay
        displayName || profile.displayName,
        userHandle,
    );
    if (!result.sessionToken) {
        throw new Error('FIDO2 register did not return sessionToken');
    }
    // The IdP echoes back the userId from our userHandle; fall back to
    // the canonical id if the server omitted it.
    const userId = result.userId || canonicalUserId;

    const account: PrivasysIdAccount = {
        userId,
        sessionToken: result.sessionToken,
        sessionExpiresAt: Date.now() + SESSION_TTL_MS,
        credentialId: result.credentialId,
        keyAlias: PRIVASYS_KEY_ALIAS,
    };
    store.setPrivasysId(account);

    return {
        sessionToken: result.sessionToken,
        userId,
        recoveryPhrase: result.recoveryPhrase,
    };
}

export function getPrivasysAccount(): PrivasysIdAccount | null {
    return useAuthStore.getState().privasysId;
}
