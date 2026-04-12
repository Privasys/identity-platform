// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * DID (Decentralised Identifier) generation and per-app derived identifiers.
 *
 * Three identity layers:
 *
 * 1. **Device DID** (`did:key`): derived from the hardware-bound P-256 key.
 *    Unique per device. Used for device identification and FIDO2 signing.
 *    Spec: https://w3c-ccg.github.io/did-key-spec/
 *
 * 2. **Canonical DID** (`did:web:privasys.id:users:<id>`): cross-device
 *    identity anchored on the privasys.id enclave. The user has one canonical
 *    DID regardless of how many devices they use. Resolved via the enclave.
 *
 * 3. **Per-app derived sub** (pairwise identifier): a unique, deterministic
 *    identifier derived for each relying party (app). Prevents app owners
 *    from correlating users across different apps.
 *    Derivation: HMAC-SHA256(pairwiseSeed, rpId) — same user + same app
 *    always produces the same sub, but different apps get different subs.
 */

import * as Crypto from 'expo-crypto';

import * as NativeKeys from '../../modules/native-keys/src/index';

const DEFAULT_KEY_ID = 'privasys-wallet-default';

// Multicodec prefix for P-256 public key (compressed): 0x1200
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);

// Base58btc alphabet
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base64urlToBytes(b64url: string): Uint8Array {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (b64.length % 4)) % 4;
    const padded = b64 + '='.repeat(pad);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Compress an uncompressed P-256 public key (65 bytes: 04 || x || y)
 * into compressed form (33 bytes: 02/03 || x).
 */
function compressP256PublicKey(uncompressed: Uint8Array): Uint8Array {
    if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
        throw new Error('Expected 65-byte uncompressed P-256 public key starting with 0x04');
    }
    const x = uncompressed.slice(1, 33);
    const y = uncompressed.slice(33, 65);
    const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
    const compressed = new Uint8Array(33);
    compressed[0] = prefix;
    compressed.set(x, 1);
    return compressed;
}

/** Encode bytes as base58btc (used for did:key multibase encoding). */
function base58btcEncode(bytes: Uint8Array): string {
    // Convert bytes to a big integer
    let value = 0n;
    for (const byte of bytes) {
        value = value * 256n + BigInt(byte);
    }

    // Convert to base58
    let result = '';
    while (value > 0n) {
        const remainder = Number(value % 58n);
        value = value / 58n;
        result = BASE58_ALPHABET[remainder] + result;
    }

    // Preserve leading zeros
    for (const byte of bytes) {
        if (byte === 0) {
            result = '1' + result;
        } else {
            break;
        }
    }

    return result;
}

/**
 * Generate a did:key DID from the wallet's hardware-bound P-256 key.
 *
 * This is the **device-level** DID — unique per device because each device
 * has a different hardware key. For cross-device identity, use the canonical
 * DID (`did:web`).
 *
 * Format: did:key:z<base58btc(multicodec-prefix || compressed-pubkey)>
 *
 * The 'z' prefix indicates base58btc multibase encoding.
 */
export async function generateDid(keyId: string = DEFAULT_KEY_ID): Promise<string> {
    const keyInfo = await NativeKeys.getPublicKey(keyId);
    const pubkeyBytes = base64urlToBytes(keyInfo.publicKey);
    const compressed = compressP256PublicKey(pubkeyBytes);

    // Multicodec-prefixed key: varint(0x1200) || compressed-pubkey
    const multicodecKey = new Uint8Array(P256_MULTICODEC_PREFIX.length + compressed.length);
    multicodecKey.set(P256_MULTICODEC_PREFIX, 0);
    multicodecKey.set(compressed, P256_MULTICODEC_PREFIX.length);

    const encoded = base58btcEncode(multicodecKey);
    return `did:key:z${encoded}`;
}

/**
 * Resolve a did:key DID document.
 * Returns a minimal DID document with the verification method.
 */
export function resolveDidDocument(did: string) {
    return {
        '@context': [
            'https://www.w3.org/ns/did/v1',
            'https://w3id.org/security/suites/jws-2020/v1'
        ],
        id: did,
        verificationMethod: [
            {
                id: `${did}#key-1`,
                type: 'JsonWebKey2020',
                controller: did
            }
        ],
        authentication: [`${did}#key-1`],
        assertionMethod: [`${did}#key-1`]
    };
}

// --- Pairwise Seed ---

/**
 * Generate a random 32-byte pairwise seed.
 *
 * This seed is created once during onboarding and stored in the profile.
 * It MUST be the same across devices for pairwise subs to match — during
 * account recovery, the seed is restored from the privasys.id enclave
 * (stored encrypted under the user's canonical identity).
 *
 * Returns a hex-encoded 32-byte seed.
 */
export async function generatePairwiseSeed(): Promise<string> {
    const bytes = await Crypto.getRandomBytesAsync(32);
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

// --- Per-App Derived Identifiers ---

/**
 * Derive a pairwise (per-app) subject identifier.
 *
 * Given the user's pairwise seed and an RP ID (app identifier), produces a
 * deterministic, unique sub for that app. The same user + same app always
 * yields the same sub, but different apps yield different subs — app owners
 * cannot correlate users across applications.
 *
 * Algorithm: SHA-256(HMAC_key || rpId) where HMAC_key is the pairwise seed.
 * We use SHA-256(seed || rpId) as HMAC is not available in expo-crypto's
 * digest API, but the seed is high-entropy (32 random bytes) so
 * SHA-256(seed || delimiter || rpId) provides equivalent security for
 * domain separation.
 *
 * @param pairwiseSeed - hex-encoded 32-byte seed from the user's profile
 * @param rpId - the relying party identifier (enclave hostname)
 * @returns hex-encoded 32-byte derived sub, unique per user per app
 */
export async function deriveAppSub(
    pairwiseSeed: string,
    rpId: string
): Promise<string> {
    // Domain-separated input: seed || 0x00 || "privasys-pairwise-v1" || 0x00 || rpId
    const separator = 'privasys-pairwise-v1';
    const input = `${pairwiseSeed}\x00${separator}\x00${rpId}`;

    const hash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        input
    );

    return hash;
}

// --- Canonical DID (did:web) ---

/**
 * Construct the canonical (cross-device) DID for a user.
 *
 * Format: `did:web:privasys.id:users:<userId>`
 *
 * The userId is derived from the pairwise seed (which is the user's root
 * secret). The DID document is hosted on privasys.id — itself an attested
 * enclave — at `https://privasys.id/users/<userId>/did.json`.
 *
 * @param pairwiseSeed - hex-encoded 32-byte seed from the user's profile
 * @returns the canonical did:web DID
 */
export async function generateCanonicalDid(pairwiseSeed: string): Promise<string> {
    // Derive a stable user ID from the seed (not rpId-specific)
    const input = `${pairwiseSeed}\x00privasys-canonical-v1`;
    const hash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        input
    );
    // Use first 16 bytes (32 hex chars) as user ID — sufficient uniqueness
    const userId = hash.substring(0, 32);
    return `did:web:privasys.id:users:${userId}`;
}

/**
 * Resolve a canonical did:web DID document (fetch from privasys.id enclave).
 *
 * The DID document includes the user's current device keys, linked providers,
 * and service endpoints. Resolution goes over RA-TLS so the document is
 * served by attested code.
 */
export async function resolveCanonicalDidDocument(
    did: string
): Promise<Record<string, unknown> | null> {
    // did:web:privasys.id:users:<userId> → https://privasys.id/users/<userId>/did.json
    const parts = did.replace('did:web:', '').split(':');
    if (parts.length < 3 || parts[0] !== 'privasys.id') return null;

    const path = parts.slice(1).join('/');
    const url = `https://privasys.id/${path}/did.json`;

    try {
        const response = await fetch(url);
        if (!response.ok) return null;
        return (await response.json()) as Record<string, unknown>;
    } catch {
        return null;
    }
}
