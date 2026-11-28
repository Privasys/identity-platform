// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * This phone proves its push token is its own.
 *
 * A push token is not a secret, and privasys.id used to take a registration's
 * word that the token belonged to the phone making it. Now the phone holds a
 * signing key for the purpose and proves the token in two steps:
 *
 *  1. privasys.id puts a nonce in the notifications it sends to the token (a
 *     sign-in request, an approval). Only the phone that receives the token's
 *     pushes sees it. The phone returns it signed (POST /push-token/bind), and
 *     its key becomes the token's. The nonce rides in notifications the holder
 *     sees because a silent push sent only to carry it did not reach this code
 *     on iOS, which decides for itself whether to wake an app for one.
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
import { getPushToken, subscribePushToken } from './push-token';

/** Nonces already answered, so a notification seen twice (shown, then opened,
 *  then found in the tray) is answered once. */
const answered = new Set<string>();

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

/** What a registration of `pushToken` for `subject` carries to be bound. */
export async function registrationProof(
    pushToken: string,
    subject: string,
): Promise<{ bind_pub: string; issued_at: number; bind_sig: string }> {
    const key = await bindKey();
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

/** A challenge that arrived before this phone knew its push token: a wallet
 *  opened by a tap handles that notification first and learns its token after.
 *  The latest one only: an older nonce has been replaced or has run out. */
let held: Record<string, unknown> | null = null;

subscribePushToken((token) => {
    if (!token || !held) return;
    const data = held;
    held = null;
    void answerBindChallenge(data).catch((e) => console.warn('[push-bind] challenge failed', e));
});

/**
 * Answer a binding challenge, when it is this phone's; held until the push
 * token is known when it is not yet.
 *
 * A challenge names the key it was opened for. Only one opened for this
 * phone's own key is answered: anything else is someone else's registration of
 * this phone's token, and signing it would hand them the token.
 */
export async function answerBindChallenge(data: Record<string, unknown> | null | undefined): Promise<boolean> {
    if (!carriesBindChallenge(data)) return false;
    const pushToken = getPushToken();
    if (!pushToken) {
        held = data!;
        return false;
    }
    const nonce = data!.bind_nonce as string;
    if (answered.has(nonce)) return false;
    const key = await bindKey();
    if (data!.bind_pub !== key.pub) return false;
    // Marked before the call: the nonce is single use at privasys.id, so a
    // second try could only be refused.
    answered.add(nonce);
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

/**
 * Forget this phone's binding key and what waits on it. Part of the wallet
 * wipe: the key is derived from the device secret the wipe deletes, and the
 * waiting registrations hold the previous identity's session.
 */
export function clearPushBindLocalState(): void {
    cached = null;
    held = null;
    waiting.clear();
    answered.clear();
}

/** Whether a notification's data carries a challenge at all. */
export function carriesBindChallenge(data: Record<string, unknown> | null | undefined): boolean {
    return typeof data?.bind_nonce === 'string' && !!data.bind_nonce && typeof data?.bind_pub === 'string';
}