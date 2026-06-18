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

import { parse as parseMrz } from 'mrz';
import { Platform } from 'react-native';
import { requireOptionalNativeModule } from 'expo-modules-core';

import type { EmrtdReadResult, EmrtdSupport, MrzKey, MrzScan } from './NativeEmrtd.types';

export type { EmrtdReadResult, EmrtdSupport, MrzKey, MrzScan };

interface NativeEmrtdModule {
    isSupported(): Promise<string>;
    readDocument(documentNumber: string, dateOfBirth: string, dateOfExpiry: string): Promise<string>;
    scanMrz(imageBase64: string): Promise<string>;
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
    const result = JSON.parse(json) as EmrtdReadResult & { error?: string; diag?: string; key?: string };
    if (result.error) {
        // Keep the key fingerprint on the error so a rejected MRZ key can be told
        // apart from a chip/comms failure when inspecting the in-app logs.
        if (result.diag) console.warn('[eMRTD] read failed:', result.error, '·', result.diag);
        // The full derived BAC key, to compare char-by-char against the passport's
        // printed MRZ when a key keeps getting rejected. (Debug; contains the
        // document number — remove once the InvalidMRZKey cause is found.)
        if (result.key) console.warn('[eMRTD] derived key:', result.key);
        throw new Error(result.diag ? `${result.error} [${result.diag}]` : result.error);
    }
    return result;
}

/**
 * OCR the machine-readable zone from a photo of the document's photo page and
 * return the chip access fields. Lets the user scan instead of typing. Throws
 * if no MRZ is found (caller falls back to manual entry).
 *
 * @param imageBase64 JPEG/PNG bytes, base64 (no data: prefix).
 */
export async function scanMrz(imageBase64: string): Promise<MrzScan> {
    if (!Native?.scanMrz) throw new Error('MRZ scanning is unavailable on this platform/build');
    const json = await Native.scanMrz(imageBase64);
    const result = JSON.parse(json) as { lines?: string[]; error?: string };
    if (result.error) throw new Error(result.error);
    const fields = parseMrzLines(result.lines ?? []);
    if (!fields) throw new Error('No valid MRZ detected');
    return fields;
}

/**
 * Pick the MRZ lines out of the OCR'd text and parse them with the `mrz`
 * library, which validates each field's ICAO check digit. We only accept a
 * result whose document-number / DOB / expiry check digits pass, so an OCR
 * misread can never produce a wrong BAC key (it just isn't returned, and the
 * caller scans the next frame).
 */
function parseMrzLines(rawLines: string[]): MrzScan | null {
    const candidates = rawLines
        .map((l) => l.toUpperCase().replace(/\s/g, ''))
        .filter((l) => /^[A-Z0-9<]{28,44}$/.test(l));

    // TD3 = 2 lines (~44 chars), TD1 = 3 lines (~30 chars).
    for (const n of [2, 3]) {
        if (candidates.length < n) continue;
        try {
            const res = parseMrz(candidates.slice(-n));
            const f = res.fields;
            // Require the check digit to PASS (true). A null/unknown result means
            // the library could not verify it (often a garbled check-digit char),
            // which previously slipped through and yielded a wrong BAC key.
            const detailValid = (field: string) => {
                const d = (res.details as Array<{ field: string; valid: boolean | null }>).find((x) => x.field === field);
                return d?.valid === true;
            };
            if (
                f.documentNumber && f.birthDate && f.expirationDate &&
                detailValid('documentNumber') && detailValid('birthDate') && detailValid('expirationDate')
            ) {
                return {
                    documentNumber: f.documentNumber,
                    dateOfBirth: f.birthDate,
                    dateOfExpiry: f.expirationDate,
                };
            }
        } catch {
            // not these lines / not an MRZ — try the next grouping
        }
    }
    return null;
}
