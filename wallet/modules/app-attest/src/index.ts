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
export async function getState(): Promise<AppAttestState> {
    const json: string = await NativeModule!.getState();
    return JSON.parse(json);
}

/**
 * Generate a new attestation key (stored in Secure Enclave on iOS).
 * Returns the keyId. Idempotent — returns existing key if already generated.
 */
export async function generateKey(): Promise<string> {
    return NativeModule!.generateKey();
}

/**
 * Attest the key with Apple/Google using the given challenge.
 * Returns the attestation object as base64.
 *
 * @param challenge Server-provided challenge (base64-encoded).
 */
export async function attestKey(challenge: string): Promise<string> {
    return NativeModule!.attestKey(challenge);
}

/**
 * Generate an assertion for the given data hash.
 * Returns the assertion as base64.
 *
 * @param clientDataHash SHA-256 of the request data (base64-encoded).
 */
export async function generateAssertion(clientDataHash: string): Promise<string> {
    return NativeModule!.generateAssertion(clientDataHash);
}
