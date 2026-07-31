// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Wallet-originated call proof.
 *
 * A priced app endpoint that declares free_for:["wallet"] is free when the
 * WALLET APP ITSELF makes the call. That is deliberately not the same as
 * "the user signed in with their wallet": a browser session the wallet
 * once approved is an ordinary paying caller. So the exemption is proved
 * per request, not carried by a session.
 *
 * Each call carries two headers the attested runtime verifies before the
 * app is reached:
 *
 *   X-Privasys-Wallet-Attestation: the WIA (wia+jwt) issued at enrolment
 *       against this device's hardware holder key. Subject-less by design,
 *       so it proves "an attested Privasys wallet" without identifying the
 *       user or their account.
 *   X-Privasys-Wallet-Proof: a short JWT signed by that holder key and
 *       bound to THIS request (method, path, freshness), so a captured
 *       attestation is useless on its own and cannot be replayed against a
 *       different endpoint.
 *
 * No access token is involved: an exempt call charges nobody, so the callee
 * never needs to learn an account, which keeps the wallet's calls as
 * unlinkable as they are today.
 */

import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';

import * as NativeKeys from '../../modules/native-keys/src/index';
import { derToRawEcdsa } from './encauth';
import { getValidWia } from './wia';

/** Same stable device holder key the WIA binds (wia.ts / kyc.ts). */
const HOLDER_KEY_ID = 'privasys-wallet-default';

export const WALLET_ATTESTATION_HEADER = 'X-Privasys-Wallet-Attestation';
export const WALLET_PROOF_HEADER = 'X-Privasys-Wallet-Proof';

const encoder = new TextEncoder();

function b64uJson(value: unknown): string {
    return bytesToBase64url(encoder.encode(JSON.stringify(value)));
}

/**
 * Build the wallet-call proof headers for one request, or undefined when
 * this device has no usable WIA (never prompts, never throws — the call
 * then proceeds as an ordinary paying caller rather than failing).
 *
 * `path` must be the exact request path the runtime will see, without the
 * query string, because the proof binds to it.
 */
export async function walletCallHeaders(
    method: string,
    path: string
): Promise<Record<string, string> | undefined> {
    try {
        const wia = await getValidWia();
        if (!wia) return undefined;

        const header = b64uJson({ alg: 'ES256', typ: 'wallet-pop+jwt' });
        const claims = b64uJson({
            htm: method.toUpperCase(),
            htu: path,
            iat: Math.floor(Date.now() / 1000)
        });
        const signingInput = `${header}.${claims}`;

        // The runtime verifies an ES256 JWS, so the DER signature the
        // platform keystore returns is converted to the JOSE raw R||S form.
        const { signature } = await NativeKeys.sign(
            HOLDER_KEY_ID,
            bytesToBase64url(encoder.encode(signingInput))
        );
        const raw = derToRawEcdsa(base64urlToBytes(signature));
        if (raw.length !== 64) throw new Error('holder signature must be 64 bytes');

        return {
            [WALLET_ATTESTATION_HEADER]: wia,
            [WALLET_PROOF_HEADER]: `${signingInput}.${bytesToBase64url(raw)}`
        };
    } catch (e) {
        console.warn('[WALLET-CALL] proof skipped:', e instanceof Error ? e.message : e);
        return undefined;
    }
}
