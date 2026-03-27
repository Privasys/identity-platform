// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';
import { requireNativeModule } from 'expo-modules-core';
import type { KeyInfo, SignatureResult } from './NativeKeys.types.js';

const NativeKeys = Platform.OS !== 'web' ? requireNativeModule('NativeKeys') : null;

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
    return JSON.parse(json);
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
 */
export async function sign(keyId: string, data: string): Promise<SignatureResult> {
    if (!NativeKeys) throw new Error('NativeKeys is not available on web');
    const json: string = await NativeKeys.sign(keyId, data);
    return JSON.parse(json);
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
    return JSON.parse(json);
}

export type { KeyInfo, SignatureResult } from './NativeKeys.types.js';
