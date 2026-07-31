// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Wallet-asserted session completion (POST /session/assert-wallet).
 *
 * The IdP stamps a non-identifying `wallet` class on tokens minted from a
 * session ONLY when an enrolled, attested wallet instance proved possession
 * of its WIA-bound holder key over that session id. The class drives the
 * free_for:["wallet"] API-fee exemption checked inside attested app
 * runtimes (identity verification from the wallet stays free), so it must
 * be unforgeable: a WebAuthn ceremony alone no longer grants it.
 *
 * Called during the sign-in approval flows, right after the FIDO2 ceremony,
 * so the holder-key signature rides the keystore's biometric grace window
 * (the same placement rationale as the EncAuth voucher). Best-effort by
 * contract: any failure means the sign-in proceeds without the class, which
 * only costs the fee exemption, never the sign-in.
 */

import * as Crypto from 'expo-crypto';

import { bytesToBase64url } from '@/utils/encoding';

import * as NativeKeys from '../../modules/native-keys/src/index';
import { ensureWia, getValidWia } from './wia';

const IDP_BASE_URL = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** Same stable device holder key the WIA binds (wia.ts / kyc.ts). */
const HOLDER_KEY_ID = 'privasys-wallet-default';

/**
 * The exact byte string the IdP verifies (it applies SHA-256 before the
 * ECDSA check, matching NativeKeys.sign). Keep in lockstep with the IdP's
 * wia.AssertPayload.
 */
function assertPayload(sessionId: string, ts: number, nonce: string): string {
    return `privasys:assert-wallet\n${sessionId}\n${ts}\n${nonce}`;
}

/**
 * Mark the pending IdP session as approved by this attested wallet
 * instance. Fire-and-forget; never throws. `allowEnrol` lets approval flows
 * (where a biometric prompt is already expected) lazily enrol the WIA on
 * first use — pass false from contexts where an extra attestation
 * round-trip would be unwelcome.
 */
export async function assertWalletSession(sessionId: string, allowEnrol = true): Promise<void> {
    try {
        if (!sessionId) return;
        const wia = allowEnrol ? await ensureWia() : await getValidWia();
        if (!wia) return; // not enrolled (e.g. simulator): no class, sign-in unaffected

        const ts = Math.floor(Date.now() / 1000);
        const nonce = bytesToBase64url(Crypto.getRandomBytes(16));
        const msg = new TextEncoder().encode(assertPayload(sessionId, ts, nonce));

        // DER ECDSA by the biometric-gated holder key, exactly what the IdP
        // verifies against the WIA's cnf.jwk.
        const { signature } = await NativeKeys.sign(HOLDER_KEY_ID, bytesToBase64url(msg));

        const res = await fetch(`${IDP_BASE_URL}/session/assert-wallet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionId,
                ts,
                nonce,
                wia,
                holder_sig: signature
            })
        });
        if (!res.ok) {
            console.warn(`[ASSERT-WALLET] IdP refused (${res.status}): ${(await res.text()).slice(0, 200)}`);
        }
    } catch (e) {
        console.warn('[ASSERT-WALLET] skipped:', e instanceof Error ? e.message : e);
    }
}
