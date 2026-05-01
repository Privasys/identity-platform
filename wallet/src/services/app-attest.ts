// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * App Attest token service.
 *
 * Obtains a short-lived JWT from the auth broker by proving the app's
 * authenticity via iOS App Attest or Android Play Integrity.
 * The returned token is used as a bearer credential when calling the
 * attestation server through the native RA-TLS verify() path.
 */

import { Platform } from 'react-native';
import * as AppAttest from '../../modules/app-attest/src/index';

const BROKER_BASE = 'https://relay.privasys.org';

/**
 * Get a short-lived attestation-server token from the broker.
 *
 * Flow:
 *   1. Ensure an App Attest key exists (generated + attested).
 *   2. Fetch a challenge from the broker.
 *   3. Generate an assertion (or attestation on first run) using the challenge.
 *   4. POST to /app-token with the attestation/assertion.
 *   5. Return the JWT.
 *
 * Recovery: if Apple rejects with `DCError.invalidInput` (numeric code 2)
 * or `DCError.invalidKey` (3), the cached keyId in the Keychain is stale
 * (the underlying Secure Enclave key is gone — typically after an app
 * reinstall, since the Keychain entry survives but App Attest keys do
 * not). We wipe state and retry the full flow exactly once.
 */
export async function getAttestationServerToken(): Promise<string> {
    try {
        return await runAttestationFlow();
    } catch (err: any) {
        if (isStaleKeyError(err)) {
            await AppAttest.reset();
            return await runAttestationFlow();
        }
        throw err;
    }
}

function isStaleKeyError(err: any): boolean {
    const msg: string = err?.message ?? String(err ?? '');
    // iOS surfaces `com.apple.devicecheck.error error N` for DCError. We
    // care about invalidInput (2) and invalidKey (3) — both indicate the
    // keyId we passed is no longer recognised by Apple's servers.
    return /devicecheck\.error error [23]\b/.test(msg);
}

async function runAttestationFlow(): Promise<string> {
    const platform = Platform.OS === 'ios' ? 'ios' : 'android';

    // 1. Ensure key is ready
    const state = await AppAttest.getState();
    let keyId: string;

    if (!state.keyId) {
        keyId = await AppAttest.generateKey();
    } else {
        keyId = state.keyId;
    }

    // 2. Get challenge from broker
    const challengeRes = await fetch(`${BROKER_BASE}/app-challenge`);
    if (!challengeRes.ok) {
        throw new Error(`Failed to get challenge: ${challengeRes.status}`);
    }
    const { challenge } = (await challengeRes.json()) as { challenge: string };

    // 3. Attest or assert
    let attestation: string;
    if (!state.attested) {
        // First time — attest the key with Apple/Google
        attestation = await AppAttest.attestKey(challenge);
    } else {
        // Already attested — generate an assertion
        attestation = await AppAttest.generateAssertion(challenge);
    }

    // 4. Exchange for JWT
    const tokenRes = await fetch(`${BROKER_BASE}/app-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            platform,
            attestation,
            keyId,
            challenge,
        }),
    });

    if (!tokenRes.ok) {
        const body = await tokenRes.text();
        throw new Error(`Token exchange failed (${tokenRes.status}): ${body}`);
    }

    const { token } = (await tokenRes.json()) as { token: string };
    return token;
}
