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
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
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
        const priv = await loadPriv();
        const shared = x25519.getSharedSecret(priv, ephPub);
        const key = hkdf(sha256, shared, undefined, new TextEncoder().encode(INFO), 32);
        const pt = xchacha20poly1305(key, nonce, new TextEncoder().encode(type)).decrypt(ct);
        return JSON.parse(new TextDecoder().decode(pt)) as Record<string, unknown>;
    } catch (e) {
        console.warn('[notify-seal] open failed', e);
        return null;
    }
}
