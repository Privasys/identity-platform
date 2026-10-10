// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Sealed app-notification payloads.
 *
 * App notifications (Drive share requests/decisions) carry their payload
 * through Expo/APNs/FCM as a sealed envelope so no attributes or content
 * ever transit third-party push infrastructure in the clear. The wallet
 * holds a device X25519 keypair; the public key is registered with the
 * IdP alongside the Expo push token, and the IdP seals each payload:
 *
 *   sealed = base64url( eph_pub(32) || nonce(24) || ct )
 *   key    = HKDF-SHA256( X25519(eph, wallet_pub), info="privasys-notify-v1" )
 *   AEAD   = XChaCha20-Poly1305, AAD = the notification type
 *
 * Mirrored by the IdP's sealToWallet (internal/admin/notify.go) and its
 * round-trip test.
 *
 * The device key above is registered only for the main account. Each service
 * identity registers its OWN key, derived from the seed and the identity:
 *
 *   sk = HKDF-SHA256(seed, info = "privasys-notify-identity/v1" ‖ 0 ‖ user id, 32)   (X25519)
 *
 * One key shared by every identity on a phone would be a value the IdP could
 * group them by. Derived keys are unrelated to each other and come back with
 * the seed after a recovery. A push does not say which key sealed it (that
 * would itself be a per-identity marker visible to Apple and Google), so the
 * wallet tries the device key, then each identity's.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { IDP_HOST, serverIdOf } from '@/services/identities';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';
import * as SecureStore from '@/utils/storage';

const KEY_STORE = 'v1-notify-seal-key';
const INFO = 'privasys-notify-v1';

function b64urlDecode(s: string): Uint8Array {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function b64urlEncode(b: Uint8Array): string {
    let bin = '';
    for (const x of b) bin += String.fromCharCode(x);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

let cachedPriv: Uint8Array | null = null;

/** Load (or create on first use) the device notification-sealing key.
 *  Returns the base64url public key to register with the push token. */
export async function ensureNotifySealKey(): Promise<string> {
    const priv = await loadPriv();
    return b64urlEncode(x25519.getPublicKey(priv));
}

async function loadPriv(): Promise<Uint8Array> {
    if (cachedPriv) return cachedPriv;
    const stored = await SecureStore.getItemAsync(KEY_STORE);
    if (stored) {
        cachedPriv = b64urlDecode(stored);
        return cachedPriv;
    }
    const priv = x25519.utils.randomSecretKey();
    await SecureStore.setItemAsync(KEY_STORE, b64urlEncode(priv));
    cachedPriv = priv;
    return priv;
}

/**
 * Drop the device notification-sealing key, in storage and in memory.
 *
 * Part of the wallet wipe — see services/wipe.ts. The next call to
 * `ensureNotifySealKey` mints a fresh key, so pushes sealed to the old identity
 * can no longer be opened on this device.
 */
export async function clearNotifySealKey(): Promise<void> {
    cachedPriv = null;
    await SecureStore.deleteItemAsync(KEY_STORE);
}

const IDENTITY_INFO = 'privasys-notify-identity/v1';

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

/** The sealing secret of one identity, or null without a seed. Exported for tests. */
export function identitySealSecret(seedHex: string, userId: string): Uint8Array {
    const label = new TextEncoder().encode(IDENTITY_INFO);
    const id = new TextEncoder().encode(userId);
    const info = new Uint8Array(label.length + 1 + id.length);
    info.set(label, 0);
    info.set(id, label.length + 1);
    return hkdf(sha256, hexToBytes(seedHex), undefined, info, 32);
}

/**
 * The public sealing key to register with this identity's push target, or ''
 * (which keeps whatever the IdP has) when there is no seed or no id.
 */
export function identitySealPub(userId: string | undefined): string {
    const seed = useProfileStore.getState().profile?.pairwiseSeed;
    if (!seed || !userId) return '';
    try {
        return b64urlEncode(x25519.getPublicKey(identitySealSecret(seed, userId)));
    } catch {
        return '';
    }
}

/** The device key, then every identity key this phone can derive. */
async function candidateKeys(): Promise<Uint8Array[]> {
    const keys: Uint8Array[] = [await loadPriv()];
    const seed = useProfileStore.getState().profile?.pairwiseSeed;
    if (!seed) return keys;
    const seen = new Set<string>();
    for (const c of useAuthStore.getState().credentials) {
        if (c.origin !== IDP_HOST || !c.userHandle) continue;
        const id = serverIdOf(c);
        if (seen.has(id)) continue;
        seen.add(id);
        try {
            keys.push(identitySealSecret(seed, id));
        } catch {
            /* a malformed seed opens nothing */
        }
    }
    return keys;
}

/** Open a sealed notification payload. Returns the parsed JSON object,
 *  or null when the envelope is malformed or not for this device's key
 *  (e.g. the key rotated since the push was sent). */
export async function openSealedNotification(
    sealed: string,
    type: string
): Promise<Record<string, unknown> | null> {
    try {
        const raw = b64urlDecode(sealed);
        if (raw.length < 32 + 24 + 16) return null;
        const ephPub = raw.slice(0, 32);
        const nonce = raw.slice(32, 56);
        const ct = raw.slice(56);
        const aad = new TextEncoder().encode(type);
        for (const priv of await candidateKeys()) {
            try {
                const shared = x25519.getSharedSecret(priv, ephPub);
                const key = hkdf(sha256, shared, undefined, new TextEncoder().encode(INFO), 32);
                const pt = xchacha20poly1305(key, nonce, aad).decrypt(ct);
                return JSON.parse(new TextDecoder().decode(pt)) as Record<string, unknown>;
            } catch {
                /* not this key; the AEAD tag says so */
            }
        }
        console.warn('[notify-seal] no key on this phone opens the notification');
        return null;
    } catch (e) {
        console.warn('[notify-seal] open failed', e);
        return null;
    }
}
