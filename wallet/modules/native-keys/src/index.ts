// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';
import { requireNativeModule } from 'expo-modules-core';
import type { KeyInfo, SignatureResult } from './NativeKeys.types.js';

const NativeKeys = Platform.OS !== 'web' ? requireNativeModule('NativeKeys') : null;

/**
 * Parse a native result, THROWING when the native side reported a failure.
 *
 * The iOS module signals failure by RETURNING `{"error":"..."}` rather than
 * rejecting (Android throws instead). Parsing that blindly handed callers an
 * object whose fields were all `undefined`, and `JSON.stringify` then dropped
 * them from request bodies entirely — so a keychain refusal on iOS travelled to
 * the server as a MISSING signature and came back as "holder proof-of-possession
 * signature is invalid" (403). The wallet reported that verbatim, which blamed
 * the cryptography for what was actually a local key-access failure, and the
 * real reason was never logged at all (2026-08-26).
 */
function parseNativeResult<T>(json: string, operation: string): T {
    const parsed = JSON.parse(json) as T & { error?: string };
    if (parsed?.error) throw new Error(`NativeKeys.${operation}: ${parsed.error}`);
    return parsed;
}

/**
 * Generate a P-256 key pair in the platform's secure hardware.
 *
 * - iOS: Secure Enclave via `SecKeyCreateRandomKey` with
 *   `kSecAttrTokenIDSecureEnclave`.
 * - Android: StrongBox or TEE via `KeyPairGenerator` with
 *   `setIsStrongBoxBacked(true)` (falls back to TEE).
 *
 * The private key never leaves the hardware — only signatures are returned.
 *
 * @param keyId  A unique identifier / alias for the key. If a key with this
 *               ID already exists, the existing key is returned.
 * @param requireBiometric  Whether signing must require biometric auth.
 * @returns Key metadata including the base64url public key.
 */
export async function generateKey(keyId: string, requireBiometric = true): Promise<KeyInfo> {
    if (!NativeKeys) throw new Error('NativeKeys is not available on web');
    const json: string = await NativeKeys.generateKey(keyId, requireBiometric);
    return parseNativeResult<KeyInfo>(json, 'generateKey');
}

/**
 * Sign arbitrary data with a hardware-backed key.
 *
 * Uses ECDSA with SHA-256. On both platforms, biometric authentication is
 * required if the key was created with `requireBiometric = true`.
 *
 * @param keyId  Key identifier (must have been created with `generateKey`).
 * @param data   Base64url-encoded data to sign.
 * @returns Base64url-encoded DER ECDSA signature.
 * @throws if the key is unavailable or the hardware refuses to sign. Callers
 *   that can proceed without a signature must catch; none may treat a missing
 *   `signature` as an empty one.
 */
export async function sign(keyId: string, data: string): Promise<SignatureResult> {
    if (!NativeKeys) throw new Error('NativeKeys is not available on web');
    const json: string = await NativeKeys.sign(keyId, data);
    return parseNativeResult<SignatureResult>(json, 'sign');
}

/**
 * Check whether a key exists in the secure hardware.
 *
 * @param keyId  Key identifier.
 * @returns `true` if the key exists.
 */
export async function keyExists(keyId: string): Promise<boolean> {
    if (!NativeKeys) throw new Error('NativeKeys is not available on web');
    return NativeKeys.keyExists(keyId);
}

/**
 * Delete a key from the secure hardware.
 *
 * @param keyId  Key identifier.
 */
export async function deleteKey(keyId: string): Promise<void> {
    if (!NativeKeys) throw new Error('NativeKeys is not available on web');
    await NativeKeys.deleteKey(keyId);
}

/**
 * Get the public key for an existing key.
 *
 * @param keyId  Key identifier.
 * @returns Key metadata, or throws if the key doesn't exist.
 */
export async function getPublicKey(keyId: string): Promise<KeyInfo> {
    if (!NativeKeys) throw new Error('NativeKeys is not available on web');
    const json: string = await NativeKeys.getPublicKey(keyId);
    return parseNativeResult<KeyInfo>(json, 'getPublicKey');
}

/**
 * iOS only. Force a fresh biometric bound to the signing context so that a
 * hardware signature issued immediately afterwards rides the same
 * authentication instead of prompting again. Use this for a sensitive step-up
 * that needs exactly one, guaranteed-fresh, clearly-labelled biometric before a
 * single signature (e.g. a vault approval). Returns `false` if the user cancels
 * or biometry is unavailable.
 *
 * On Android the hardware signature does not present its own prompt, so callers
 * should gate with the OS biometric directly rather than calling this.
 */
export async function authenticateForSigning(reason: string): Promise<boolean> {
    if (!NativeKeys) throw new Error('NativeKeys is not available on web');
    return NativeKeys.authenticateForSigning(reason);
}

export type { KeyInfo, SignatureResult } from './NativeKeys.types.js';
