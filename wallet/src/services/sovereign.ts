// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Sovereign data root (the sovereign-data framework, Phase 2).
 *
 * The wallet holds one 32-byte data root R, generated on first use and
 * kept in secure storage. Per-app data keys derive from it:
 *
 *   W = HKDF-SHA256(R, info = "privasys-sovereign/w/v1" || 0x00 ||
 *                             pairwise_sub || 0x00 || app_id_hex)
 *
 * so apps stay pairwise-unlinkable and nothing per-app needs storing.
 * W is released ONLY to an app whose enclave attestation verified
 * (status === 'verified'); there is deliberately no override path.
 *
 * Backup: R (and the pairwise seed, whose promised backup this file is
 * the first real implementation of) are wrapped under material derived
 * from the 24-word recovery phrase and stored IdP-side as one opaque
 * blob. The KEK derives from the phrase's decoded ENTROPY, not its
 * string form, so it is invariant to the whitespace/case differences
 * the normaliser forgives. Envelope:
 *
 *   blob = base64url( 0x01 || salt(16) || nonce(24) || ct )
 *   kek  = HKDF-SHA256( bip39_entropy(phrase), salt,
 *                       info = "privasys-sovereign/backup/v1" )
 *   ct   = XChaCha20-Poly1305(kek, nonce,
 *                             AAD = "privasys-sovereign-backup")
 *            .encrypt(utf8(JSON{v, data_root, pairwise_seed}))
 *
 * The IdP never sees plaintext: it stores ciphertext keyed to material
 * it does not hold (it keeps only sha256(phrase), which cannot yield
 * the HKDF input). Wrapping always uses the exact server-returned
 * phrase string, never a user transcription, so a mistyped note cannot
 * corrupt the blob. Re-wrap happens at every ceremony where the wallet
 * momentarily holds the phrase: first registration, regeneration, and
 * recovery (the entered phrase unwraps the old blob; the user is then
 * prompted to generate a new phrase, which re-wraps).
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as Crypto from 'expo-crypto';
import * as SecureStore from '@/utils/storage';
import { bytesToBase64url, base64urlToBytes } from '@/utils/encoding';
import { mnemonicToEntropy, normaliseMnemonic } from '@/services/bip39';
import { getSovereignBackup, putSovereignBackup } from '@/services/sovereign-api';

const ROOT_KEY = 'privasys.sovereign-root';
const W_INFO = 'privasys-sovereign/w/v1';
const BACKUP_INFO = 'privasys-sovereign/backup/v1';
const BACKUP_AAD = 'privasys-sovereign-backup';
const BLOB_VERSION = 0x01;

const utf8 = (s: string) => new TextEncoder().encode(s);

let cachedRoot: Uint8Array | null = null;
let inflight: Promise<Uint8Array> | null = null;

/** Load (or create on first use) the 32-byte sovereign data root. */
export async function ensureDataRoot(): Promise<Uint8Array> {
    if (cachedRoot) return cachedRoot;
    if (inflight) return inflight;
    inflight = (async () => {
        const stored = await SecureStore.getItemAsync(ROOT_KEY);
        if (stored) {
            cachedRoot = base64urlToBytes(stored);
            return cachedRoot;
        }
        const root = new Uint8Array(await Crypto.getRandomBytesAsync(32));
        await SecureStore.setItemAsync(ROOT_KEY, bytesToBase64url(root));
        cachedRoot = root;
        return root;
    })();
    try {
        return await inflight;
    } finally {
        inflight = null;
    }
}

/** The stored root, or null if none exists yet (never generates). */
export async function peekDataRoot(): Promise<Uint8Array | null> {
    if (cachedRoot) return cachedRoot;
    const stored = await SecureStore.getItemAsync(ROOT_KEY);
    if (!stored) return null;
    cachedRoot = base64urlToBytes(stored);
    return cachedRoot;
}

/**
 * Install a recovered root (the account-recovery restore path). Refuses
 * to overwrite an existing DIFFERENT root: two roots means two disjoint
 * key families, and silently replacing one would orphan every W derived
 * from the other — surface that condition instead of picking a side.
 */
export async function installDataRoot(root: Uint8Array): Promise<void> {
    const existing = await peekDataRoot();
    if (existing && bytesToBase64url(existing) !== bytesToBase64url(root)) {
        throw new Error(
            'sovereign: a different data root already exists on this device; refusing to overwrite'
        );
    }
    await SecureStore.setItemAsync(ROOT_KEY, bytesToBase64url(root));
    cachedRoot = root;
}

/** Pure derivation of a per-app key W. Deterministic; 32 bytes. */
export function deriveW(root: Uint8Array, pairwiseSub: string, appIdHex: string): Uint8Array {
    const label = utf8(W_INFO);
    const sub = utf8(pairwiseSub);
    const app = utf8(appIdHex.toLowerCase());
    const info = new Uint8Array(label.length + 1 + sub.length + 1 + app.length);
    info.set(label, 0);
    info[label.length] = 0x00;
    info.set(sub, label.length + 1);
    info[label.length + 1 + sub.length] = 0x00;
    info.set(app, label.length + 2 + sub.length);
    return hkdf(sha256, root, undefined, info, 32);
}

/**
 * Release the per-app key W for an ATTESTED app. The outcome must come
 * from attestEnclave and be 'verified' — 'unreachable' (no AS token) is
 * NOT acceptable here and there is no user-override path: this key
 * unlocks the user's data, so the gate fails closed like the KYC and
 * Drive flows do.
 */
export async function sovereignKeyForAttestedApp(
    outcome: { status: string },
    pairwiseSub: string,
    appIdHex: string
): Promise<Uint8Array> {
    if (outcome.status !== 'verified') {
        throw new Error(
            `sovereign: refusing to release the data key — app attestation is '${outcome.status}', not 'verified'`
        );
    }
    if (!appIdHex) {
        throw new Error('sovereign: attested app has no app id (OID 3.6); refusing');
    }
    const root = await ensureDataRoot();
    return deriveW(root, pairwiseSub, appIdHex);
}

/** What the backup envelope protects. */
export interface SovereignBackupPayload {
    dataRootB64: string;
    pairwiseSeedHex: string | null;
}

/** Wrap the payload under phrase-derived material. Throws on an invalid phrase. */
export function wrapSovereignBackup(phrase: string, payload: SovereignBackupPayload): string {
    const entropy = mnemonicToEntropy(normaliseMnemonic(phrase));
    if (!entropy) {
        throw new Error('sovereign: recovery phrase failed BIP39 validation; refusing to wrap');
    }
    const salt = new Uint8Array(Crypto.getRandomBytes(16));
    const nonce = new Uint8Array(Crypto.getRandomBytes(24));
    const kek = hkdf(sha256, entropy, salt, utf8(BACKUP_INFO), 32);
    const pt = utf8(
        JSON.stringify({
            v: 1,
            data_root: payload.dataRootB64,
            pairwise_seed: payload.pairwiseSeedHex,
        })
    );
    const ct = xchacha20poly1305(kek, nonce, utf8(BACKUP_AAD)).encrypt(pt);
    const blob = new Uint8Array(1 + salt.length + nonce.length + ct.length);
    blob[0] = BLOB_VERSION;
    blob.set(salt, 1);
    blob.set(nonce, 17);
    blob.set(ct, 41);
    return bytesToBase64url(blob);
}

/** Unwrap a backup blob. Returns null on a wrong phrase or tampered blob. */
export function unwrapSovereignBackup(phrase: string, blobB64: string): SovereignBackupPayload | null {
    try {
        const entropy = mnemonicToEntropy(normaliseMnemonic(phrase));
        if (!entropy) return null;
        const raw = base64urlToBytes(blobB64);
        if (raw.length < 1 + 16 + 24 + 16 || raw[0] !== BLOB_VERSION) return null;
        const salt = raw.slice(1, 17);
        const nonce = raw.slice(17, 41);
        const ct = raw.slice(41);
        const kek = hkdf(sha256, entropy, salt, utf8(BACKUP_INFO), 32);
        const pt = xchacha20poly1305(kek, nonce, utf8(BACKUP_AAD)).decrypt(ct);
        const parsed = JSON.parse(new TextDecoder().decode(pt)) as {
            v: number;
            data_root: string;
            pairwise_seed: string | null;
        };
        if (parsed.v !== 1 || !parsed.data_root) return null;
        return { dataRootB64: parsed.data_root, pairwiseSeedHex: parsed.pairwise_seed ?? null };
    } catch {
        return null;
    }
}

/**
 * Wrap the wallet's root secrets under the given phrase and store the
 * blob IdP-side. Called from every ceremony that holds the phrase.
 * Throws on failure so callers can surface it — a silently missing
 * backup defeats the whole point.
 */
export async function backupSovereignSecrets(
    phrase: string,
    pairwiseSeedHex: string | null,
    walletSessionToken: string
): Promise<void> {
    const root = await ensureDataRoot();
    const blob = wrapSovereignBackup(phrase, {
        dataRootB64: bytesToBase64url(root),
        pairwiseSeedHex,
    });
    await putSovereignBackup(walletSessionToken, blob);
}

/**
 * Fetch and unwrap the backup after account recovery. Returns the
 * recovered pairwise seed for the caller to apply to the profile store
 * (this service stays store-free), or null when no blob exists (a
 * pre-framework account) or the phrase does not open it.
 */
export async function restoreSovereignSecrets(
    phrase: string,
    walletSessionToken: string
): Promise<{ pairwiseSeedHex: string | null } | null> {
    const blob = await getSovereignBackup(walletSessionToken);
    if (!blob) return null;
    const payload = unwrapSovereignBackup(phrase, blob);
    if (!payload) {
        console.warn('[sovereign] backup blob present but could not be opened with the entered phrase');
        return null;
    }
    await installDataRoot(base64urlToBytes(payload.dataRootB64));
    return { pairwiseSeedHex: payload.pairwiseSeedHex };
}

// ── Recovered pairwise-seed hand-off ────────────────────────────────
//
// The pairwise seed is device-global, so a recovered seed can only be
// applied where no profile exists yet (a fresh recovery device). The
// recovery screen stashes it here; both profile-creation paths (first-run
// setup and the connect auto-create) prefer it over minting a fresh one,
// which is what makes pairwise identities survive device loss. On a
// device that already has a profile with a DIFFERENT seed, overwriting
// would silently rotate every derived sub for every account on the
// device — so the stash is left untouched and the caller warns instead.

const RECOVERED_SEED_KEY = 'privasys.sovereign.recovered-seed';

/** Stash a recovered pairwise seed for the next profile creation. */
export async function stashRecoveredPairwiseSeed(seedHex: string): Promise<void> {
    await SecureStore.setItemAsync(RECOVERED_SEED_KEY, seedHex);
}

/** Take (and clear) a stashed recovered pairwise seed, if any. */
export async function takeRecoveredPairwiseSeed(): Promise<string | null> {
    const seed = await SecureStore.getItemAsync(RECOVERED_SEED_KEY);
    if (seed) await SecureStore.deleteItemAsync(RECOVERED_SEED_KEY);
    return seed || null;
}

/** Test hook: drop the in-memory root cache. */
export function __clearRootCacheForTests(): void {
    cachedRoot = null;
}
