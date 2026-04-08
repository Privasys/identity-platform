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
 */
export async function getAttestationServerToken(): Promise<string> {
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
