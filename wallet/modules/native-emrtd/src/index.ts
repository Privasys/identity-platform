// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * eMRTD (ICAO 9303 passport / national-ID chip) NFC reader.
 *
 * Reads DG1 (MRZ fields), DG2 (portrait), and EF.SOD over NFC after unlocking
 * the chip with the MRZ-derived BAC/PACE key, so the wallet can forward them to
 * the attested verifier enclave for Passive + Chip Authentication and the face
 * match. The raw chip data stays on the device except for that RA-TLS hop to
 * the enclave (see services/kyc.ts), per the data-locality invariant.
 *
 * Uses `requireOptionalNativeModule` so the JS bundle loads even where the
 * native module isn't present (web, Expo Go, simulator) — callers gate on
 * `isSupported()` and fall back accordingly.
 */

import { Platform } from 'react-native';
import { requireOptionalNativeModule } from 'expo-modules-core';

import type { EmrtdReadResult, EmrtdSupport, MrzKey } from './NativeEmrtd.types';

export type { EmrtdReadResult, EmrtdSupport, MrzKey };

interface NativeEmrtdModule {
    isSupported(): Promise<string>;
    readDocument(documentNumber: string, dateOfBirth: string, dateOfExpiry: string): Promise<string>;
}

const Native =
    Platform.OS !== 'web' ? requireOptionalNativeModule<NativeEmrtdModule>('NativeEmrtd') : null;

/** Whether the device can read eMRTD chips over NFC right now. */
export async function isSupported(): Promise<EmrtdSupport> {
    if (!Native) return { supported: false, reason: 'NFC reader unavailable on this platform/build' };
    try {
        return JSON.parse(await Native.isSupported()) as EmrtdSupport;
    } catch (e: any) {
        return { supported: false, reason: e?.message ?? 'availability check failed' };
    }
}

/**
 * Read the document chip. Throws if unsupported or the read fails (e.g. wrong
 * MRZ key, chip moved away). The MRZ key is derived from the document number +
 * date of birth + date of expiry (OCR'd or hand-entered).
 */
export async function readDocument(key: MrzKey): Promise<EmrtdReadResult> {
    if (!Native) throw new Error('eMRTD reader is unavailable on this platform/build');
    const json = await Native.readDocument(key.documentNumber, key.dateOfBirth, key.dateOfExpiry);
    const result = JSON.parse(json) as EmrtdReadResult & { error?: string };
    if (result.error) throw new Error(result.error);
    return result;
}
