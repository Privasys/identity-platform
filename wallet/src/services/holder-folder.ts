// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The key to a holder folder: the holder's files kept in an app's own storage,
 * which the app can open only while the holder allows it.
 *
 * The enclave OS binds the folder to 64 bytes the wallet sends with the mint.
 * Three properties matter, and they decide how those bytes are made:
 *
 * 1. The SAME bytes for the same app every time. After an enclave restart, or
 *    a revoke and a fresh approval, the folder reopens only if the wallet sends
 *    what it sent the first time.
 * 2. They survive losing the phone. A lost key is a folder nobody can open,
 *    with the holder's files inside it.
 * 3. They are bound to the app the WALLET verified, never to an id the request
 *    supplied. Keyed by a requested id, one app could name another's and be
 *    handed that app's folder key.
 *
 * So they are DERIVED from the sovereign data root rather than generated and
 * stored. The root is already in the phrase-wrapped backup and restored on
 * recovery, so every folder key is too, from the moment it is first used. A
 * random key kept in the secure store would not be: the backup can only be
 * re-wrapped while the wallet holds the recovery phrase, which is during a
 * phrase ceremony and never during an approval, so a fresh random key would sit
 * on the phone alone until the holder next regenerated their phrase, which most
 * never do. Derivation also needs nothing stored per app.
 *
 *   K = HKDF-SHA256(root, salt = none,
 *                   info = "privasys-holder-folder/v1" || 0x00 || app_id_hex,
 *                   length = 64)
 *
 * Domain-separated from the per-app data key W in services/sovereign.ts by its
 * own info label, so the two are independent even for the same app.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { ensureDataRoot } from '@/services/sovereign';
import { bytesToBase64 } from '@/utils/encoding';

/** What the enclave OS expects, and refuses (400) at any other length. */
export const HOLDER_FOLDER_KEY_BYTES = 64;

const FOLDER_INFO = 'privasys-holder-folder/v1';

/**
 * One spelling per app. The attested id arrives dashed and other paths carry it
 * bare; a key that depended on the spelling would open a different folder for
 * the same app.
 */
export function normaliseAppId(appId: string): string {
    const hex = appId.trim().toLowerCase().replace(/-/g, '');
    if (!/^[0-9a-f]{32}$/.test(hex)) {
        throw new Error('holder folder: not an app id');
    }
    return hex;
}

/** Pure derivation. Deterministic; 64 bytes. */
export function deriveHolderFolderKey(root: Uint8Array, appId: string): Uint8Array {
    const label = new TextEncoder().encode(FOLDER_INFO);
    const app = new TextEncoder().encode(normaliseAppId(appId));
    const info = new Uint8Array(label.length + 1 + app.length);
    info.set(label, 0);
    info[label.length] = 0x00;
    info.set(app, label.length + 1);
    return hkdf(sha256, root, undefined, info, HOLDER_FOLDER_KEY_BYTES);
}

/**
 * The key for this app, standard base64, ready for the mint's `setup.key_b64`.
 *
 * `attestedAppId` must be the id the wallet read from the app's attestation,
 * never a value out of the request. Never logged.
 */
export async function holderFolderKeyB64(attestedAppId: string): Promise<string> {
    const root = await ensureDataRoot();
    return bytesToBase64(deriveHolderFolderKey(root, attestedAppId));
}
