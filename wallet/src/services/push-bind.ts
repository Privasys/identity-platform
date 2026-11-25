// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * This phone proves its push token is its own.
 *
 * A push token is not a secret, and privasys.id used to take a registration's
 * word that the token belonged to the phone making it. Now the phone holds a
 * signing key for the purpose and proves the token in two steps:
 *
 *  1. privasys.id pushes a nonce to the token. Only the phone that receives
 *     the token's pushes sees it. The phone returns it signed
 *     (POST /push-token/bind), and its key becomes the token's.
 *  2. Each identity on the phone registers the token with a signature, under
 *     that key, over its own subject. That is what binds an identity: the
 *     phone never signs for a subject it does not hold.
 *
 * Only a bound registration is counted for the icon's number or treated as one
 * of the holder's other phones, and clearing a notification elsewhere is
 * signed with the same key.
 *
 * The key is derived from this phone's device secret, so it never leaves the
 * phone and a reinstall makes a new one, proven by a new challenge.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { base64urlToBytes, bytesToBase64url } from '../utils/encoding';

/** The silent push that carries a challenge. */
export const BIND_TYPE = 'push-bind';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const KEY_INFO = 'privasys-push-bind-key/v1';

const utf8 = (s: string) => new TextEncoder().encode(s);

interface BindKey {
    pub: string;
    secret: Uint8Array;
}

let cached: BindKey | null = null;

/** This phone's binding key. Loaded when first needed: the device module is
 *  not part of what the wallet loads to answer a push in the background. */
async function bindKey(): Promise<BindKey> {
    if (cached) return cached;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { ensureDevice } = require('./devices') as typeof import('./devices');
    const device = await ensureDevice();
    const secret = hmac(sha256, base64urlToBytes(device.secret), utf8(KEY_INFO));
    cached = { pub: bytesToBase64url(ed25519.getPublicKey(secret)), secret };
    return cached;
}

const sign = (key: BindKey, text: string) => bytesToBase64url(ed25519.sign(utf8(text), key.secret));
const nowSeconds = () => Math.floor(Date.now() / 1000);

/** What a registration of `pushToken` for `subject` carries to be bound. With
 *  no subject only the key is named, and the registration stays unbound. */
export async function registrationProof(
    pushToken: string,
    subject?: string,
): Promise<{ bind_pub: string; issued_at?: number; bind_sig?: string }> {
    const key = await bindKey();
    if (!subject) return { bind_pub: key.pub };
    const issuedAt = nowSeconds();
    return {
        bind_pub: key.pub,
        issued_at: issuedAt,
        bind_sig: sign(key, `privasys-push-register/v1\n${pushToken}\n${subject}\n${issuedAt}`),
    };
}

/** What a request to clear a notification on the holder's other phones carries. */
export async function dismissProof(pushToken: string, key: string): Promise<{ issued_at: number; sig: string }> {
    const issuedAt = nowSeconds();
    return {
        issued_at: issuedAt,
        sig: sign(await bindKey(), `privasys-push-dismiss/v1\n${pushToken}\n${key}\n${issuedAt}`),
    };
}

/** Registrations that came back unbound, to make again once the key is proven.
 *  One per identity, the latest. Held in memory: a session is not written down
 *  for this, and the next sign-in registers again anyway. */
const waiting = new Map<string, () => Promise<unknown>>();

/** Remember a registration to repeat when this phone's key has been proven. */
export function repeatWhenBound(subject: string, register: () => Promise<unknown>): void {
    waiting.set(subject, register);
}

/**
 * Answer a binding challenge, when it is this phone's.
 *
 * A challenge names the key it was opened for. Only one opened for this
 * phone's own key is answered: anything else is someone else's registration of
 * this phone's token, and signing it would hand them the token.
 */
export async function answerBindChallenge(data: Record<string, unknown> | null | undefined, pushToken: string | null): Promise<boolean> {
    const nonce = data?.nonce;
    if (!pushToken || typeof nonce !== 'string' || !nonce || typeof data?.bind_pub !== 'string') return false;
    const key = await bindKey();
    if (data.bind_pub !== key.pub) return false;
    const res = await fetch(`${IDP_BASE}/push-token/bind`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            push_token: pushToken,
            bind_pub: key.pub,
            nonce,
            sig: sign(key, `privasys-push-bind/v1\n${pushToken}\n${nonce}`),
        }),
    });
    if (!res.ok) return false;
    // The key is the token's now: each identity registers again, signed.
    const again = [...waiting.values()];
    waiting.clear();
    await Promise.all(again.map((register) => register().catch(() => undefined)));
    return true;
}

/** For tests. */
export function resetPushBind(): void {
    cached = null;
    waiting.clear();
}
