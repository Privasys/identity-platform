// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Locale packs: fetch once, verify, cache, reuse.
 *
 * Only `en-GB` is compiled into the binary. Every other language is a JSON
 * pack of roughly 25KB downloaded the first time it is selected and then
 * read from disk forever after.
 *
 * ── Why the digest check is not optional ────────────────────────────────
 * The consent screens are a security control. They are the surface where a
 * user reads what an app is asking for and decides. An attacker who can
 * rewrite a locale pack does not need to touch the grant at all: they can
 * turn "Share your date of birth and passport number" into "Confirm your
 * session" and the user taps the same button.
 *
 * So the trust root is the binary, never the network. The JS bundle carries
 * a manifest of SHA-256 digests, one per pack (i18n/manifest.ts, generated).
 * A pack that does not match its digest is discarded and the wallet stays on
 * en-GB. There is no "warn and continue" path: mistranslated-looking copy is
 * a nuisance, attacker-chosen copy on a consent screen is not.
 *
 * The cost of that choice, accepted deliberately: copy can only change by
 * shipping a bundle, because the digest list ships with the bundle.
 *
 * ── Why the manifest version is not the app version ─────────────────────
 * app.config.ts sets `runtimeVersion: { policy: 'appVersion' }`, so an EAS
 * Update can change copy without changing the app version. Keying packs on
 * the app version would serve pre-update copy to updated clients. The
 * manifest version is derived from the pack contents instead, so it moves
 * exactly when the copy moves.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { Directory, File, Paths } from 'expo-file-system';

import { I18N_MANIFEST } from './manifest';
import { FALLBACK_LOCALE, negotiateLocale } from './locales';

/** Same origin the wallet already talks to, so packs add no new host. */
const PACK_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** Give up rather than hang a language switch on a stalled network. */
const FETCH_TIMEOUT_MS = 15_000;

/** Cache root: <documents>/i18n/<manifestVersion>/<tag>.json */
const CACHE_DIR = 'i18n';

export type PackResult =
    | { ok: true; resources: Record<string, unknown>; from: 'cache' | 'network' }
    | { ok: false; reason: 'unsupported' | 'no-digest' | 'network' | 'digest-mismatch' | 'malformed' };

function packDir(): Directory {
    return new Directory(Paths.document, CACHE_DIR, I18N_MANIFEST.version);
}

function packFile(tag: string): File {
    return new File(packDir(), `${tag}.json`);
}

/** hex(sha256(bytes)), matching the manifest generator's digest. */
export function digestHex(bytes: Uint8Array): string {
    return bytesToHex(sha256(bytes));
}

/**
 * Constant-time-ish comparison. Digests are public values so timing is not
 * really a concern here, but a length-then-content compare avoids the
 * short-circuit habit leaking into code where it would matter.
 */
function digestsMatch(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

function parseResources(text: string): Record<string, unknown> | null {
    try {
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
        return parsed as Record<string, unknown>;
    } catch {
        return null;
    }
}

/** Read a verified pack from disk, or null if absent or no longer valid. */
function readCached(tag: string, expected: string): Record<string, unknown> | null {
    try {
        const file = packFile(tag);
        if (!file.exists) return null;
        // Synchronous read: this runs on the language-resolution path and the
        // caller is already async, but keeping the verify-then-parse sequence
        // atomic is easier to reason about than interleaving awaits with a
        // file that could change underneath us.
        const bytes = file.bytesSync();
        // Re-verify on every read. The cache lives in the app sandbox, but a
        // digest check that only runs at download time is one rooted-device
        // file write away from being no check at all.
        if (!digestsMatch(digestHex(bytes), expected)) {
            file.delete();
            return null;
        }
        return parseResources(new TextDecoder().decode(bytes));
    } catch {
        return null;
    }
}

function writeCached(tag: string, bytes: Uint8Array): void {
    try {
        const dir = packDir();
        if (!dir.exists) dir.create({ intermediates: true });
        const file = packFile(tag);
        if (file.exists) file.delete();
        file.create();
        file.write(bytes);
    } catch {
        // A cache write failure costs one refetch next launch, nothing more.
    }
}

async function fetchPack(tag: string): Promise<Uint8Array | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
        const url = `${PACK_BASE}/i18n/${I18N_MANIFEST.version}/${tag}.json`;
        // No credentials, no cookies, no auth header. This is a static asset
        // fetch and must not become a way to correlate a language with a
        // session.
        const res = await fetch(url, {
            method: 'GET',
            credentials: 'omit',
            signal: controller.signal,
            headers: { Accept: 'application/json' },
        });
        if (!res.ok) return null;
        return new Uint8Array(await res.arrayBuffer());
    } catch {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

/**
 * Get the resource bundle for `tag`, from cache when possible.
 *
 * Never throws. Every failure path returns `ok: false` and leaves the caller
 * on whatever language it already had, which is at worst the compiled-in
 * en-GB. No screen should ever be blocked on this.
 */
export async function loadPack(tag: string): Promise<PackResult> {
    const resolved = negotiateLocale(tag);
    if (resolved === FALLBACK_LOCALE) return { ok: false, reason: 'unsupported' };

    const expected = I18N_MANIFEST.digests[resolved];
    if (!expected) return { ok: false, reason: 'no-digest' };

    const cached = readCached(resolved, expected);
    if (cached) return { ok: true, resources: cached, from: 'cache' };

    const bytes = await fetchPack(resolved);
    if (!bytes) return { ok: false, reason: 'network' };

    if (!digestsMatch(digestHex(bytes), expected)) {
        // Served content does not match what this build was signed to expect.
        // Discard it; do not cache it; do not render it.
        return { ok: false, reason: 'digest-mismatch' };
    }

    const resources = parseResources(new TextDecoder().decode(bytes));
    if (!resources) return { ok: false, reason: 'malformed' };

    writeCached(resolved, bytes);
    return { ok: true, resources, from: 'network' };
}

/** Whether `tag` is already on disk, so selecting it needs no network. */
export function isPackCached(tag: string): boolean {
    const resolved = negotiateLocale(tag);
    const expected = I18N_MANIFEST.digests[resolved];
    return !!expected && readCached(resolved, expected) !== null;
}

/**
 * Is this language usable right now, without a download?
 *
 * Existence only. {@link isPackCached} re-reads and re-hashes the whole file,
 * which is the right thing on the load path and the wrong thing for a list
 * that asks about 25 locales every render.
 *
 * `en-GB` is compiled into the binary and has no manifest entry, so it is
 * always available; asking the digest map about it returns undefined and
 * would otherwise render the source language as "needs downloading" forever.
 *
 * Cheapness is safe here because this only drives an icon. Nothing is
 * rendered from a pack until loadPack has verified its digest.
 */
export function isPackAvailable(tag: string): boolean {
    const resolved = negotiateLocale(tag);
    if (resolved === FALLBACK_LOCALE) return true;
    if (!I18N_MANIFEST.digests[resolved]) return false;
    try {
        return packFile(resolved).exists;
    } catch {
        return false;
    }
}

/**
 * Delete packs from superseded manifest versions.
 *
 * Called after a successful load rather than at launch: an upgrade that
 * changes the manifest should not spend startup time on file IO, and if the
 * purge never runs the only cost is disk.
 */
export function purgeStalePacks(): void {
    try {
        const root = new Directory(Paths.document, CACHE_DIR);
        if (!root.exists) return;
        for (const entry of root.list()) {
            if (entry instanceof Directory && entry.name !== I18N_MANIFEST.version) {
                entry.delete();
            }
        }
    } catch {
        // Best effort. Stale packs are inert: they are only ever read from
        // the current version's directory.
    }
}
