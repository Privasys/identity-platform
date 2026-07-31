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
        let credId = existing.credentialId;
        let keyAlias = existing.keyAlias;
        let userId = existing.userId;
        // The slot's userId has historically been stored in two forms: the
        // raw 32-hex canonical id (early builds kept the local fallback) and
        // its base64url userHandle encoding (what the IdP echoes back).
        // credentials[] records the b64url userHandle, so a same-account
        // match must accept either form or the repair below never fires.
        const slotHandles = new Set([existing.userId, b64url(existing.userId)]);
        const sameAccount = (c: { rpId: string; userHandle?: string }) =>
            c.rpId === 'privasys.id' && !!c.userHandle && slotHandles.has(c.userHandle);
        const adoptIntoSlot = (adopt: (typeof store.credentials)[number]) => {
            credId = adopt.credentialId;
            keyAlias = adopt.keyAlias;
            userId = adopt.userHandle ?? existing.userId;
            store.setPrivasysId({
                ...existing,
                userId,
                credentialId: credId,
                keyAlias,
                sessionToken: '',
                sessionExpiresAt: 0,
            });
            store.removeCredential(adopt.credentialId);
        };
        // Self-heal an empty slot credentialId (left by a slot-unaware recovery):
        // authenticating with no credentialId sends the IdP down its discoverable
        // path, which 404s "no credentials found for user" — the confusing error
        // users hit when reconfiguring the phrase after recovery. Adopt the
        // account's credential from credentials[] (matched by userHandle) if one
        // is there; otherwise fail with a clear, actionable message.
        if (!credId) {
            const adopt = store.credentials.find(sameAccount);
            if (!adopt) {
                throw new Error(
                    'This device has no privasys.id credential for your account. ' +
                    'Recover your account or sign in again to re-register this device.',
                );
            }
            adoptIntoSlot(adopt);
        }
        const authenticate = (cid: string, alias: string) =>
            fido2Authenticate(
                PRIVASYS_ORIGIN,
                alias,
                cid,
                '', // no browser session relay
                PRIVASYS_ORIGIN,
            );
        let result;
        try {
            result = await authenticate(credId, keyAlias);
        } catch (e: any) {
            // The server no longer knows the slot's credential (a recovery
            // revoked it). If credentials[] holds another credential for the
            // SAME account (matched by userHandle), the slot pointer is just
            // stale — repoint it and retry once. Local repair only; never
            // re-register automatically.
            const stale = String(e?.message ?? e).includes('no credentials found');
            const adopt = stale
                ? store.credentials.find((c) => sameAccount(c) && c.credentialId !== credId)
                : undefined;
            if (!adopt) {
                if (stale) {
                    // Nothing adoptable — surface the device state so the
                    // mismatch is diagnosable from the error alone.
                    const held = store.credentials
                        .filter((c) => c.rpId === 'privasys.id')
                        .map((c) => `${c.credentialId.slice(0, 8)}…@${(c.userHandle ?? 'no-handle').slice(0, 8)}…`)
                        .join(', ') || 'none';
                    throw new Error(
                        `The server has no credential ${credId.slice(0, 8)}… for account ` +
                        `${existing.userId.slice(0, 8)}… and this device holds no other credential ` +
                        `for that account (privasys.id credentials held: ${held}). ` +
                        'Recover your account to re-register this device.',
                    );
                }
                throw e;
            }
            adoptIntoSlot(adopt);
            result = await authenticate(credId, keyAlias);
        }
        if (!result.sessionToken) throw new Error('No sessionToken from authenticate');
        store.setPrivasysSession(result.sessionToken, SESSION_TTL_MS);
        return { sessionToken: result.sessionToken, userId };
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

/**
 * The canonical meta-account's IdP user id (the userHandle its credential was
 * registered under), derived from the on-device pairwise seed. Lets flows that
 * touch a recovered/registered identity decide whether it IS the canonical
 * account — which lives in the dedicated `privasysId` slot — or a pairwise
 * one, which lives in `credentials[]`. Returns null when the profile is not
 * initialised.
 */
export async function canonicalUserHandle(): Promise<string | null> {
    const profile = useProfileStore.getState().profile;
    if (!profile?.pairwiseSeed) return null;
    return b64url(await deriveCanonicalUserId(profile.pairwiseSeed));
}
