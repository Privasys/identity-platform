// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's keys for the Privasys verifiers, derived from the seed.
 *
 * Every device of the holder holds the seed, so every device derives the same
 * key: a proof one device imported can be rebound to another by the verifier
 * that signed it, while disclosing still needs the device's own hardware key.
 *
 * One key per verifier, never one root key for all: a single key's hash seen
 * by privasys.id, the control plane and each verifier would be one identifier
 * linking the holder across all of them.
 *
 *   okm    = HKDF-SHA256(ikm = seed bytes, salt = empty, info, 48 bytes)
 *   scalar = okm mapped into [1, n-1] of P-256 (big-endian, as noble's
 *            mapHashToField), 32 bytes
 *   pub    = SEC1 uncompressed point, 65 bytes
 *
 * Wherever a third party sees the key (a provider's sign-in nonce, the card
 * check), it sees a commitment instead, salted afresh each time so that two
 * imports or two checks cannot be linked:
 *
 *   commitment = base64url( SHA-256( pub || salt ) ), salt = 16 random bytes
 *
 * The salt is kept with the raw material it was used for, so the verifier can
 * recompute the commitment from pub and salt.
 */

import { mapHashToField } from '@noble/curves/abstract/modular.js';
import { p256 } from '@noble/curves/nist.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';

/** The verifiers the holder has a key for: the HKDF info of each. */
export const HOLDER_KEY_INFO = {
    attribute: 'privasys-attribute-verifier/v1',
    identity: 'privasys-identity-verifier/v1',
} as const;

export type HolderVerifier = keyof typeof HOLDER_KEY_INFO;

export interface HolderKey {
    /** The private scalar, 32 bytes. Kept in memory only while signing. */
    secretKey: Uint8Array;
    /** SEC1 uncompressed, 65 bytes. */
    publicKey: Uint8Array;
}

function hexToBytes(hex: string): Uint8Array {
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) throw new Error('holder-keys: the seed is not hex');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

/** The holder's key for one verifier, from the seed (hex, as the profile keeps it). */
export function deriveHolderKey(seedHex: string, verifier: HolderVerifier): HolderKey {
    const okm = hkdf(sha256, hexToBytes(seedHex), new Uint8Array(0), new TextEncoder().encode(HOLDER_KEY_INFO[verifier]), 48);
    const secretKey = mapHashToField(okm, p256.Point.Fn.ORDER);
    return { secretKey, publicKey: p256.getPublicKey(secretKey, false) };
}

/** A commitment to the holder's key: base64url(SHA-256(pub || salt)). */
export function holderCommitment(publicKey: Uint8Array, salt: Uint8Array): string {
    if (salt.length !== 16) throw new Error('holder-keys: the salt is 16 bytes');
    const joined = new Uint8Array(publicKey.length + salt.length);
    joined.set(publicKey, 0);
    joined.set(salt, publicKey.length);
    return bytesToBase64url(sha256(joined));
}

/** Whether a commitment is to this key with this salt. */
export function opensCommitment(commitment: string, publicKey: Uint8Array, salt: Uint8Array): boolean {
    try {
        return bytesToBase64url(base64urlToBytes(commitment)) === holderCommitment(publicKey, salt);
    } catch {
        return false;
    }
}
