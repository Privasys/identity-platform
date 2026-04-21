// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Privasys ID meta-account — the wallet's own account at privasys.id used
 * for recovery management (not for signing into external apps).
 *
 * The first time the user opens recovery settings, the wallet registers a
 * dedicated FIDO2 credential against the `privasys.id` RP. This credential
 * never leaves the device and is used solely to obtain wallet sessionTokens
 * for managing the recovery phrase, guardians, and registered devices.
 */

import { register as fido2Register, authenticate as fido2Authenticate } from './fido2';
import { useAuthStore, type PrivasysIdAccount } from '@/stores/auth';

const PRIVASYS_ORIGIN = 'privasys.id';
const PRIVASYS_KEY_ALIAS = 'privasys-id-account';
const SESSION_TTL_MS = 25 * 60 * 1000; // 25 min (server is 30, leave margin)

/**
 * Ensure we have a fresh wallet sessionToken for the privasys.id account.
 * Registers on first call, re-authenticates on subsequent calls when the
 * cached session has expired.
 *
 * Both register and authenticate require biometric user verification.
 *
 * @returns the sessionToken to use as `Bearer wallet:<token>`
 */
export async function ensurePrivasysSession(displayName?: string): Promise<{ sessionToken: string; userId: string; recoveryPhrase?: string }> {
    const store = useAuthStore.getState();
    const existing = store.privasysId;

    // Cached session still valid?
    if (existing && existing.sessionToken && Date.now() < existing.sessionExpiresAt) {
        return { sessionToken: existing.sessionToken, userId: existing.userId };
    }

    if (existing) {
        // Re-authenticate
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

    // First-time registration
    const result = await fido2Register(
        PRIVASYS_ORIGIN,
        PRIVASYS_KEY_ALIAS,
        '', // no browser session relay
        displayName,
    );
    if (!result.sessionToken || !result.userId) {
        throw new Error('FIDO2 register did not return sessionToken/userId');
    }

    const account: PrivasysIdAccount = {
        userId: result.userId,
        sessionToken: result.sessionToken,
        sessionExpiresAt: Date.now() + SESSION_TTL_MS,
        credentialId: result.credentialId,
        keyAlias: PRIVASYS_KEY_ALIAS,
    };
    store.setPrivasysId(account);

    return {
        sessionToken: result.sessionToken,
        userId: result.userId,
        recoveryPhrase: result.recoveryPhrase,
    };
}

export function getPrivasysAccount(): PrivasysIdAccount | null {
    return useAuthStore.getState().privasysId;
}
