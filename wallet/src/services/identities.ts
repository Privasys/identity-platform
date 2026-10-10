// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The identities the wallet presents to services, made so they survive losing
 * the phone.
 *
 * The wallet shows each relying party a different identity, and only the
 * wallet knows they belong to one person. Their handles used to be random, and
 * a phrase recovery brought back the main account and nothing else: a new
 * phone signing in to Drive created a new Drive identity, and the old one, with
 * everything it owned, was stranded.
 *
 * Two changes fix it.
 *
 * 1. A NEW identity's handle is derived from the pairwise seed and the relying
 *    party, so a recovered seed names it again:
 *
 *      handle = base64url( HKDF-SHA256(seed, info = "privasys-identity/v1" ‖ 0 ‖ rpId, 32) )
 *
 *    To anyone without the seed two derived handles are unrelated, so the
 *    identities stay unlinkable.
 *
 * 2. EVERY identity at privasys.id registers a recovery key, once, derived from
 *    the seed and the identity's own handle:
 *
 *      sk = HKDF-SHA256(seed, info = "privasys-identity-recovery/v1" ‖ 0 ‖ handle, 32)   (Ed25519 seed)
 *
 *    On a new phone the wallet re-derives sk and signs the IdP's challenge for
 *    that identity, which completes a recovery of that identity alone (see the
 *    IdP's internal/recovery/identity.go). No request names more than one
 *    identity, so the IdP never learns which identities are one person's.
 *
 * Identities made before this have random handles that no seed re-derives. The
 * wallet keeps the list of those it holds (the identity index), encrypted under
 * a key from the sovereign data root, on the main account. A recovered phone
 * gets the root back from the phrase-wrapped backup and reads the list. The list
 * never grows: every identity made from now on is derived.
 *
 * Recovery is lazy: an identity comes back at the first sign-in to its service,
 * not all at once, which would group them by time and address.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as Crypto from 'expo-crypto';

import { ensureDataRoot } from '@/services/sovereign';
import { useAuthStore, type Credential } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
/** The FIDO2 server host identities are recovered at. */
export const IDP_HOST = IDP_BASE.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

const HANDLE_INFO = 'privasys-identity/v1';
const RECOVERY_INFO = 'privasys-identity-recovery/v1';
const RECOVERY_DOMAIN = 'privasys-identity-recovery/v1';
const INDEX_INFO = 'privasys-identity-index/v1';
const INDEX_AAD = 'privasys-identity-index';
const INDEX_VERSION = 0x01;

/** Handles whose recovery key the IdP has accepted, so it is sent once. */
const PROTECTED_KEY = 'privasys.identities.protected';
/** Identities with random handles, restored from the index after a recovery. */
const LEGACY_KEY = 'privasys.identities.legacy';
/** Fingerprint of the last index uploaded, to skip no-op writes. */
const INDEX_SYNCED_KEY = 'privasys.identities.index-synced';

const utf8 = (s: string) => new TextEncoder().encode(s);

function infoFor(label: string, value: string): Uint8Array {
    const a = utf8(label);
    const b = utf8(value);
    const out = new Uint8Array(a.length + 1 + b.length);
    out.set(a, 0);
    out[a.length] = 0;
    out.set(b, a.length + 1);
    return out;
}

function hexToBytes(hex: string): Uint8Array {
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) throw new Error('identities: seed is not hex');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

// ---------------------------------------------------------------- derivation

/** The handle of the identity this wallet presents to `rpId`. */
export function deriveIdentityHandle(seedHex: string, rpId: string): string {
    return bytesToBase64url(hkdf(sha256, hexToBytes(seedHex), undefined, infoFor(HANDLE_INFO, rpId), 32));
}

/** The recovery key pair of the identity with this handle. */
export function deriveRecoveryKey(seedHex: string, userHandle: string): { secretKey: Uint8Array; publicKey: Uint8Array } {
    const secretKey = hkdf(sha256, hexToBytes(seedHex), undefined, infoFor(RECOVERY_INFO, userHandle), 32);
    return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

/** The bytes a recovery key signs: domain ‖ 0 ‖ user id ‖ 0 ‖ challenge. Must match the IdP. */
export function recoveryMessage(userId: string, challenge: Uint8Array): Uint8Array {
    const head = infoFor(RECOVERY_DOMAIN, userId);
    const out = new Uint8Array(head.length + 1 + challenge.length);
    out.set(head, 0);
    out[head.length] = 0;
    out.set(challenge, head.length + 1);
    return out;
}

function currentSeed(): string | null {
    return useProfileStore.getState().profile?.pairwiseSeed ?? null;
}

// ---------------------------------------------------------------- legacy identities

/** An identity made before handles were derived. */
export interface LegacyIdentity {
    rpId: string;
    userHandle: string;
}

async function readJson<T>(key: string, fallback: T): Promise<T> {
    try {
        const raw = await SecureStore.getItemAsync(key);
        return raw ? (JSON.parse(raw) as T) : fallback;
    } catch {
        return fallback;
    }
}

async function legacyIdentities(): Promise<LegacyIdentity[]> {
    return readJson<LegacyIdentity[]>(LEGACY_KEY, []);
}

/**
 * The handle to register for `rpId` when this phone holds no credential for it.
 * A legacy identity restored from the index comes first, because that is the one
 * that owns things; otherwise the derived handle. Null without a seed, in which
 * case the caller registers a random identity as before.
 */
export async function handleForNewCredential(rpId: string): Promise<string | null> {
    const legacy = (await legacyIdentities()).find((l) => l.rpId === rpId);
    if (legacy) return legacy.userHandle;
    const seed = currentSeed();
    return seed ? deriveIdentityHandle(seed, rpId) : null;
}

// ---------------------------------------------------------------- IdP calls

async function idpJson<T>(path: string, init: RequestInit): Promise<{ status: number; body: T | null }> {
    const res = await fetch(`${IDP_BASE}${path}`, init);
    let body: T | null = null;
    try {
        body = (await res.json()) as T;
    } catch {
        body = null;
    }
    return { status: res.status, body };
}

/** True when a registration was refused because the account already exists. */
export function isRecoveryRequired(e: unknown): boolean {
    return /requires account recovery/i.test(String((e as any)?.message ?? e));
}

/**
 * Prove ownership of one identity and complete its recovery, so this phone may
 * register a passkey on it. Throws with the IdP's reason on failure.
 */
export async function recoverIdentity(userHandle: string): Promise<void> {
    const seed = currentSeed();
    if (!seed) throw new Error('identities: no seed on this phone');
    const begin = await idpJson<{ challenge?: string; error?: string }>('/recovery/identity/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userHandle }),
    });
    if (begin.status !== 200 || !begin.body?.challenge) {
        throw new Error(begin.body?.error ?? `identity recovery could not start (HTTP ${begin.status})`);
    }
    const challenge = base64urlToBytes(begin.body.challenge);
    const { secretKey } = deriveRecoveryKey(seed, userHandle);
    const signature = ed25519.sign(recoveryMessage(userHandle, challenge), secretKey);
    const done = await idpJson<{ error?: string }>('/recovery/identity/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            user_id: userHandle,
            challenge: begin.body.challenge,
            signature: bytesToBase64url(signature),
        }),
    });
    if (done.status !== 200) {
        throw new Error(done.body?.error ?? `identity recovery failed (HTTP ${done.status})`);
    }
}

/**
 * Register this identity's recovery key with the IdP, once. Best effort and
 * silent: a failure is retried at the next sign-in. `sessionToken` is the
 * identity's own wallet session, from the ceremony that just completed.
 */
export async function protectIdentity(sessionToken: string, userHandle: string): Promise<void> {
    const seed = currentSeed();
    if (!seed || !sessionToken || !userHandle) return;
    try {
        const done = await readJson<string[]>(PROTECTED_KEY, []);
        if (done.includes(userHandle)) return;
        const { publicKey } = deriveRecoveryKey(seed, userHandle);
        const res = await fetch(`${IDP_BASE}/recovery/identity-key`, {
            method: 'PUT',
            headers: { Authorization: `Bearer wallet:${sessionToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ public_key: bytesToBase64url(publicKey) }),
        });
        // 409: a different key is already there. That happens only if the seed
        // changed under this identity; nothing here can fix it, so stop asking.
        if (res.ok || res.status === 409) {
            if (res.status === 409) console.warn('[identities] the IdP holds a different recovery key for this identity');
            await SecureStore.setItemAsync(PROTECTED_KEY, JSON.stringify([...done, userHandle]));
        }
    } catch (e: any) {
        console.warn('[identities] could not register the recovery key:', e?.message ?? e);
    }
}

// ---------------------------------------------------------------- identity index

function isIdpCredential(c: Credential): boolean {
    return c.origin === IDP_HOST;
}

/**
 * The IdP's user id for a stored credential. The wallet registers with a
 * handle (the user id, as text) and the IdP echoes it back as WebAuthn
 * `user.id`, which is that text base64url-encoded again, and that echo is what
 * `Credential.userHandle` holds. Decode it once; a value that does not decode
 * to base64url text is already the user id.
 */
export function serverIdOf(c: Pick<Credential, 'userHandle'>): string {
    try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(base64urlToBytes(c.userHandle));
        if (/^[A-Za-z0-9_-]{16,}$/.test(text)) return text;
    } catch {
        /* not double-encoded */
    }
    return c.userHandle;
}

/**
 * The main account's handle, as privasys-id.ts registers it: the first 32 hex
 * characters of SHA-256(seed ‖ 0 ‖ "privasys-canonical-v1"), base64url-encoded
 * as text. It is recovered by the phrase, never listed as an identity.
 */
export function canonicalHandle(seedHex: string): string {
    const digest = sha256(utf8(`${seedHex}\x00privasys-canonical-v1`));
    let hex = '';
    for (const b of digest) hex += b.toString(16).padStart(2, '0');
    return bytesToBase64url(utf8(hex.substring(0, 32)));
}

/**
 * Identities on this phone whose handle the seed does not derive, the one this
 * phone signs in as first for each relying party (the holder's pick, else the
 * newest), since that is the one a recovery should bring back first.
 */
export function legacyFromCredentials(
    credentials: Credential[],
    seedHex: string,
    activeCredentialId: string | null = null,
): LegacyIdentity[] {
    const main = canonicalHandle(seedHex);
    const ordered = [...credentials].sort((a, b) => {
        if (a.credentialId === activeCredentialId) return -1;
        if (b.credentialId === activeCredentialId) return 1;
        return (b.registeredAt ?? 0) - (a.registeredAt ?? 0);
    });
    const seen = new Set<string>();
    const out: LegacyIdentity[] = [];
    for (const c of ordered) {
        if (!isIdpCredential(c) || !c.userHandle) continue;
        const id = serverIdOf(c);
        if (id === main || id === deriveIdentityHandle(seedHex, c.rpId) || seen.has(id)) continue;
        seen.add(id);
        out.push({ rpId: c.rpId, userHandle: id });
    }
    return out;
}

async function indexKey(): Promise<Uint8Array> {
    return hkdf(sha256, await ensureDataRoot(), undefined, utf8(INDEX_INFO), 32);
}

/** Encrypt the identity index. Exported for tests. */
export function sealIndex(key: Uint8Array, entries: LegacyIdentity[]): string {
    const nonce = new Uint8Array(Crypto.getRandomBytes(24));
    const ct = xchacha20poly1305(key, nonce, utf8(INDEX_AAD)).encrypt(utf8(JSON.stringify({ v: 1, identities: entries })));
    const blob = new Uint8Array(1 + 24 + ct.length);
    blob[0] = INDEX_VERSION;
    blob.set(nonce, 1);
    blob.set(ct, 25);
    return bytesToBase64url(blob);
}

/** Decrypt the identity index, or null when it does not open. Exported for tests. */
export function openIndex(key: Uint8Array, blobB64: string): LegacyIdentity[] | null {
    try {
        const raw = base64urlToBytes(blobB64);
        if (raw.length < 1 + 24 + 16 || raw[0] !== INDEX_VERSION) return null;
        const pt = xchacha20poly1305(key, raw.slice(1, 25), utf8(INDEX_AAD)).decrypt(raw.slice(25));
        const parsed = JSON.parse(new TextDecoder().decode(pt)) as { v: number; identities: LegacyIdentity[] };
        if (parsed.v !== 1 || !Array.isArray(parsed.identities)) return null;
        return parsed.identities.filter((e) => typeof e?.rpId === 'string' && typeof e?.userHandle === 'string');
    } catch {
        return null;
    }
}

// Order matters (the first entry per relying party is recovered first), so the
// fingerprint covers it.
function fingerprint(entries: LegacyIdentity[]): string {
    return bytesToBase64url(sha256(utf8(JSON.stringify(entries))));
}

/**
 * Upload the identity index when it has changed, using the main account's
 * session only if one is already open: this never asks for Face ID. Called
 * after sign-ins and from the recovery screen, which opens that session anyway.
 */
export async function syncIdentityIndex(): Promise<void> {
    try {
        const seed = currentSeed();
        const account = useAuthStore.getState().privasysId;
        if (!seed || !account?.sessionToken || Date.now() >= account.sessionExpiresAt) return;
        // What this phone holds now, in sign-in order, then what a recovery
        // restored and the phone has not signed in to yet.
        const auth = useAuthStore.getState();
        const merged = new Map<string, LegacyIdentity>();
        for (const e of [
            ...legacyFromCredentials(auth.credentials, seed, auth.activeCredentialId),
            ...(await legacyIdentities()),
        ]) {
            if (!merged.has(e.userHandle)) merged.set(e.userHandle, e);
        }
        const entries = [...merged.values()];
        if (entries.length === 0) return;
        const fp = fingerprint(entries);
        if ((await SecureStore.getItemAsync(INDEX_SYNCED_KEY)) === fp) return;
        const res = await fetch(`${IDP_BASE}/recovery/identity-index`, {
            method: 'PUT',
            headers: { Authorization: `Bearer wallet:${account.sessionToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ blob: sealIndex(await indexKey(), entries) }),
        });
        if (res.ok) await SecureStore.setItemAsync(INDEX_SYNCED_KEY, fp);
    } catch (e: any) {
        console.warn('[identities] identity index sync failed:', e?.message ?? e);
    }
}

/**
 * After a phrase recovery: fetch the identity index with the main account's
 * fresh session and keep its entries, so each legacy identity is recovered at
 * its next sign-in. Needs the data root restored first. Returns how many.
 */
export async function restoreIdentityIndex(canonicalSessionToken: string): Promise<number> {
    const res = await fetch(`${IDP_BASE}/recovery/identity-index`, {
        headers: { Authorization: `Bearer wallet:${canonicalSessionToken}` },
    });
    if (res.status === 404) return 0;
    if (!res.ok) throw new Error(`identity index could not be read (HTTP ${res.status})`);
    const { blob } = (await res.json()) as { blob: string };
    const entries = openIndex(await indexKey(), blob);
    if (!entries) throw new Error('identity index did not open with the restored data root');
    await SecureStore.setItemAsync(LEGACY_KEY, JSON.stringify(entries));
    await SecureStore.setItemAsync(INDEX_SYNCED_KEY, fingerprint(entries));
    return entries.length;
}

/** Part of Clear All Data. */
export async function clearIdentitiesLocalState(): Promise<void> {
    await SecureStore.deleteItemAsync(PROTECTED_KEY);
    await SecureStore.deleteItemAsync(LEGACY_KEY);
    await SecureStore.deleteItemAsync(INDEX_SYNCED_KEY);
}
