// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';
import { requireNativeModule } from 'expo-modules-core';
import type { AppAttestState } from './AppAttest.types';

export type { AppAttestState };

const NativeModule =
    Platform.OS !== 'web' ? requireNativeModule('AppAttest') : null;

/**
 * Check whether App Attest (iOS) / Play Integrity (Android) is available,
 * and whether a key has already been generated and attested.
 */
export async function getState(scope?: string): Promise<AppAttestState> {
    const json: string = await NativeModule!.getState(scope ?? null);
    return JSON.parse(json);
}

/**
 * Generate a new attestation key (stored in Secure Enclave on iOS).
 * Returns the keyId. Idempotent — returns existing key if already generated.
 *
 * @param scope Optional key namespace. Omit for the legacy shared key; the
 *   WIA flow uses a fresh scoped key per enrolment so every enrol carries a
 *   FULL attestation object (a key attests once — assertions cannot satisfy
 *   the IdP's strict mode).
 */
export async function generateKey(scope?: string): Promise<string> {
    return NativeModule!.generateKey(scope ?? null);
}

/**
 * Attest the key with Apple/Google using the given challenge.
 * Returns the attestation object as base64.
 *
 * @param challenge Server-provided challenge (base64-encoded).
 * @param scope Optional key namespace (see generateKey).
 */
export async function attestKey(challenge: string, scope?: string): Promise<string> {
    return NativeModule!.attestKey(challenge, scope ?? null);
}

/**
 * Generate an assertion for the given data hash.
 * Returns the assertion as base64.
 *
 * @param clientDataHash SHA-256 of the request data (base64-encoded).
 * @param scope Optional key namespace (see generateKey).
 */
export async function generateAssertion(clientDataHash: string, scope?: string): Promise<string> {
    return NativeModule!.generateAssertion(clientDataHash, scope ?? null);
}

/**
 * Wipe the cached keyId and attested flag. Use to recover from a stale
 * keyId in the Keychain whose underlying Secure Enclave key is gone
 * (Apple rejects with `DCError.invalidInput` / `error 2`), or to force a
 * fresh scoped key (the WIA per-enrolment key).
 */
export async function reset(scope?: string): Promise<void> {
    if (NativeModule && typeof NativeModule.reset === 'function') {
        await NativeModule.reset(scope ?? null);
    }
}
