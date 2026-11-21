// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Passkeys for other websites: on this device only, or backed up to the
 * holder's devices.
 *
 * The wallet is a general passkey provider (modules/passkey-provider). A
 * website passkey is either made in the secure chip and never leaves this
 * device ("local"), or derived from the holder's seed so every device of the
 * holder can derive it again ("synced"). The provider (an iOS extension, an
 * Android service) never holds the seed: the wallet gives it one secret for
 * website passkeys only, the passkey root:
 *
 *   root   = HKDF-SHA256(seed bytes, salt = empty, info = "privasys-website-passkeys/v1", 32)
 *   id     = 0x01 || r                      (r: 16 random bytes, chosen by the provider)
 *   scalar = (BE(HKDF-SHA256(root, salt = r, info = "privasys-website-passkey/v1" 0x00 rpId, 48)) mod (n - 1)) + 1
 *
 * The provider derives a synced passkey's key from its credential id each
 * time it signs. Here: the root, the list of synced passkeys the holder's
 * devices share, and the count the warnings give.
 */

import { mapHashToField } from '@noble/curves/abstract/modular.js';
import { p256 } from '@noble/curves/nist.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { bytesToBase64url } from '@/utils/encoding';

import * as NativeKeys from '../../modules/native-keys/src/index';

const ROOT_INFO = 'privasys-website-passkeys/v1';
const KEY_INFO = 'privasys-website-passkey/v1';

export interface WebsitePasskey {
    rpId: string;
    /** base64url */
    credentialId: string;
    userName: string;
    /** base64url */
    userHandle: string;
    kind: 'local' | 'synced';
    createdAt: number;
}

function hexToBytes(hex: string): Uint8Array {
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) throw new Error('website-passkeys: the seed is not hex');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

/** The passkey root: the only secret the passkey provider holds. */
export function passkeyRoot(seedHex: string): Uint8Array {
    return hkdf(sha256, hexToBytes(seedHex), new Uint8Array(0), new TextEncoder().encode(ROOT_INFO), 32);
}

/**
 * A synced passkey's private scalar, as the provider derives it. Kept here so
 * the test vectors the native code is checked against come from one place.
 */
export function syncedPasskeyScalar(root: Uint8Array, r: Uint8Array, rpId: string): Uint8Array {
    const label = new TextEncoder().encode(`${KEY_INFO}\x00${rpId}`);
    return mapHashToField(hkdf(sha256, root, r, label, 48), p256.Point.Fn.ORDER);
}

/** Give the provider the root, from the profile's seed. Best effort; idempotent. */
export async function installPasskeyRoot(seedHex: string | undefined): Promise<void> {
    if (!seedHex) return;
    try {
        await NativeKeys.setPasskeyRoot(bytesToBase64url(passkeyRoot(seedHex)));
    } catch (e: any) {
        console.warn('[website-passkeys] root not installed:', e?.message ?? e);
    }
}

/** Part of Clear All Data. */
export async function clearPasskeyRoot(): Promise<void> {
    try {
        await NativeKeys.clearPasskeyRoot();
    } catch {
        /* nothing to clear */
    }
}

/** Every website passkey this device holds, both kinds. */
export async function listWebsitePasskeys(): Promise<WebsitePasskey[]> {
    try {
        const parsed = JSON.parse(await NativeKeys.listWebsitePasskeys());
        return Array.isArray(parsed) ? (parsed as WebsitePasskey[]) : [];
    } catch {
        return [];
    }
}

/** The synced passkeys, for the holder's other devices and the profile copy. */
export async function syncedWebsitePasskeys(): Promise<WebsitePasskey[]> {
    return (await listWebsitePasskeys()).filter((p) => p.kind === 'synced');
}

/** Take in synced passkeys made on another device. Returns how many were new. */
export async function importSyncedWebsitePasskeys(list: WebsitePasskey[] | undefined): Promise<number> {
    const synced = (list ?? []).filter((p) => p.kind === 'synced');
    if (synced.length === 0) return 0;
    try {
        return await NativeKeys.importWebsitePasskeys(JSON.stringify(synced));
    } catch (e: any) {
        console.warn('[website-passkeys] import failed:', e?.message ?? e);
        return 0;
    }
}

/** How many of this device's website passkeys would be lost with it. */
export async function localWebsitePasskeyCount(): Promise<number> {
    return (await listWebsitePasskeys()).filter((p) => p.kind !== 'synced').length;
}
