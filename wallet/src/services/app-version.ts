// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Minimum supported wallet version.
 *
 * Some releases fix things a user cannot work around and cannot see. The wallet
 * shipped for two days unable to complete an identity verification on either
 * platform while reporting nothing that pointed at the cause, and there was no
 * way to tell the installed base to move. This is that way.
 *
 * A small JSON document at {@link MANIFEST_URL} names, per platform, the oldest
 * version still considered good and what happens below it: `recommended` shows a
 * notice the user can dismiss, `required` shows one they cannot. The document
 * also carries the explanation, because the reason a version is retired is
 * specific to that release and cannot be shipped in a catalogue written before
 * it existed.
 *
 * ## Trust
 *
 * The document is SIGNED, and the signature is checked against a key pinned in
 * this bundle before anything else is read. privasys.id serves an ordinary
 * certificate today (the RA-TLS client accepts quote-less certs and enforces
 * only when a quote is present), so without the pin a forged certificate would
 * be enough to publish `required` against an impossible version and wall every
 * wallet at once. This is a remote kill switch; a mis-issued cert should not be
 * able to pull it.
 *
 * The signature is over the payload bytes verbatim, so there is no canonical
 * form to agree on and no room for a parser difference between what was signed
 * and what is read. See {@link openEnvelope}.
 *
 * Suppression is the other half and no signature fixes it: an attacker who
 * blocks the request simply keeps a wallet on an old version. So a verdict once
 * seen is REMEMBERED, and going offline does not lift a wall that was already
 * raised.
 *
 * Every failure here means NO FLOOR: an unsigned document, an unknown key, a
 * bad signature and a malformed payload all land in the same place as an
 * unreachable server. That direction is deliberate and is the reason an empty
 * key map is a safe default.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import Constants from 'expo-constants';
import { Platform } from 'react-native';

import { VERSION_SIGNING_KEYS } from '@/services/version-signing-keys';
import { base64urlToBytes } from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';
import { withTimeout } from '@/utils/timeout';

const IDP_BASE_URL = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** Mutable and singular, unlike the content-addressed locale packs. */
export const MANIFEST_URL = `${IDP_BASE_URL}/wallet/version.json`;

const STORE_KEY = 'privasys.app-version-verdict';

/** Long enough for a slow network, short enough that launch never waits on it. */
const FETCH_TIMEOUT_MS = 8_000;

/** What being below the floor does. */
export type UpdateLevel = 'recommended' | 'required';

/** The user-facing half of a manifest entry, in one language. */
export interface UpdateText {
    title: string;
    body: string;
    /** What stops working, and why. One line each. */
    changes: string[];
}

/** A resolved verdict: this build is below the floor, and here is the case. */
export interface UpdateNotice {
    /**
     * Identifies this notice, so a dismissal applies to THIS message and a
     * later one nags again. Dismissing "please update for the passport fix"
     * must not also dismiss whatever comes next.
     */
    id: string;
    /** The floor this build failed. */
    minimum: string;
    /** The build that failed it. */
    current: string;
    level: UpdateLevel;
    text: UpdateText;
    learnMoreUrl?: string;
}

interface StoredVerdict {
    notice: UpdateNotice | null;
    /** Manifest `issuedAt`, epoch ms. Guards against replaying an older one. */
    issuedAt: number;
    /** Notice ids the user has dismissed. Only ever consulted for `recommended`. */
    dismissed: string[];
}

/**
 * Compare two `X.Y.Z` versions.
 *
 * Returns <0, 0 or >0. Missing or non-numeric components count as 0, so a
 * malformed version never throws and never accidentally clears a floor: it
 * compares as the lowest possible build, which errs toward showing the notice
 * rather than hiding it.
 */
export function compareVersions(a: string, b: string): number {
    const parse = (v: string) =>
        String(v ?? '')
            .split('.')
            .map((part) => {
                const n = Number.parseInt(part, 10);
                return Number.isFinite(n) && n >= 0 ? n : 0;
            });
    const left = parse(a);
    const right = parse(b);
    const width = Math.max(left.length, right.length, 3);
    for (let i = 0; i < width; i++) {
        const d = (left[i] ?? 0) - (right[i] ?? 0);
        if (d !== 0) return d < 0 ? -1 : 1;
    }
    return 0;
}

/** This build's marketing version, as `app.config.ts` recorded it. */
export function currentVersion(): string {
    const extra = (Constants.expoConfig?.extra ?? {}) as Record<string, string | undefined>;
    return extra.CODE_VERSION ?? (Constants.expoConfig?.version as string | undefined) ?? '0.0.0';
}

/**
 * What the server actually serves: a signed envelope around the document.
 *
 * The payload travels base64url-encoded rather than inline so the bytes that
 * were signed are the bytes that are verified, with no canonical-JSON question
 * to get wrong. Whitespace, key order and unicode escaping all stop mattering.
 */
interface Envelope {
    keyId?: string;
    payload?: string;
    sig?: string;
}

/**
 * Verify an envelope and return the document text, or null.
 *
 * Null for every reason: not an envelope, a key this build does not carry, a
 * signature that does not check out. The caller treats null exactly as it
 * treats an unreachable server, so a wallet is never walled by something it
 * could not verify.
 *
 * @param keys pinned keyId -> base64url public key. Empty means nothing
 *   verifies, which leaves the gate inert rather than open.
 */
export function openEnvelope(
    raw: unknown,
    keys: Readonly<Record<string, string>> = VERSION_SIGNING_KEYS,
): string | null {
    if (!raw || typeof raw !== 'object') return null;
    const env = raw as Envelope;
    if (typeof env.keyId !== 'string' || typeof env.payload !== 'string' || typeof env.sig !== 'string') {
        return null;
    }
    const publicKey = keys[env.keyId];
    if (!publicKey) {
        console.warn(`[version] document signed by an unknown key (${env.keyId}); ignoring`);
        return null;
    }
    try {
        const payload = base64urlToBytes(env.payload);
        const ok = ed25519.verify(base64urlToBytes(env.sig), payload, base64urlToBytes(publicKey));
        if (!ok) {
            console.warn('[version] document signature did not verify; ignoring');
            return null;
        }
        return new TextDecoder().decode(payload);
    } catch (e) {
        // A malformed base64 or a wrong-length key lands here. Same answer.
        console.warn('[version] could not check the document signature:', e instanceof Error ? e.message : e);
        return null;
    }
}

/** The raw document. Everything here is untrusted input from the network. */
interface RawManifest {
    schema?: number;
    issuedAt?: string;
    platforms?: Record<string, { minimum?: string; level?: string } | undefined>;
    notice?: {
        id?: string;
        learnMoreUrl?: string;
        text?: Record<string, Partial<UpdateText> | undefined>;
    };
}

/**
 * Turn a fetched document into a verdict for THIS build, or null.
 *
 * Every field is checked, because a wallet that walls itself on a malformed
 * document is worse than one that ignores it: the failure mode of this whole
 * feature is locking people out of their own identity. Anything unrecognised
 * means no notice.
 *
 * A signature check belongs here, ahead of everything else, if and when the
 * document is signed.
 */
export function parseManifest(
    raw: unknown,
    opts: { platform: string; version: string; language: string },
): { notice: UpdateNotice | null; issuedAt: number } | null {
    if (!raw || typeof raw !== 'object') return null;
    const doc = raw as RawManifest;
    if (doc.schema !== 1) return null;

    const issuedAt = Date.parse(String(doc.issuedAt ?? ''));
    if (!Number.isFinite(issuedAt)) return null;

    const entry = doc.platforms?.[opts.platform];
    // A platform absent from the document has no floor. That is how a fix for
    // one platform is pushed without touching the other.
    if (!entry || typeof entry.minimum !== 'string') return { notice: null, issuedAt };

    const level: UpdateLevel = entry.level === 'required' ? 'required' : 'recommended';
    if (compareVersions(opts.version, entry.minimum) >= 0) return { notice: null, issuedAt };

    const text = pickText(doc.notice?.text, opts.language);
    // A floor with nothing to say is not shown. The user is being asked to act;
    // "update, because" with no because is how people learn to ignore this.
    if (!text) return { notice: null, issuedAt };

    return {
        issuedAt,
        notice: {
            id: String(doc.notice?.id ?? `${opts.platform}-${entry.minimum}`),
            minimum: entry.minimum,
            current: opts.version,
            level,
            text,
            learnMoreUrl: typeof doc.notice?.learnMoreUrl === 'string' ? doc.notice.learnMoreUrl : undefined,
        },
    };
}

/**
 * The notice in the user's language, falling back to the bare language and then
 * to English.
 *
 * The prose is server-supplied because it describes a release that did not
 * exist when the app was built, so it cannot come from the app's own
 * catalogue. Everything AROUND it (the title bar, the buttons, "Update
 * required") does come from the catalogue and is translated properly.
 */
function pickText(
    texts: Record<string, Partial<UpdateText> | undefined> | undefined,
    language: string,
): UpdateText | null {
    if (!texts) return null;
    const base = language.split('-')[0];
    for (const key of [language, base, 'en-GB', 'en']) {
        const candidate = key ? texts[key] : undefined;
        if (!candidate) continue;
        const title = typeof candidate.title === 'string' ? candidate.title.trim() : '';
        const body = typeof candidate.body === 'string' ? candidate.body.trim() : '';
        if (!title || !body) continue;
        const changes = Array.isArray(candidate.changes)
            ? candidate.changes.filter((c): c is string => typeof c === 'string' && c.trim() !== '')
            : [];
        return { title, body, changes };
    }
    return null;
}

/** Read the remembered verdict. Never throws; a corrupt record is no record. */
export async function loadVerdict(): Promise<StoredVerdict> {
    try {
        const rawJson = await SecureStore.getItemAsync(STORE_KEY);
        if (!rawJson) return { notice: null, issuedAt: 0, dismissed: [] };
        const parsed = JSON.parse(rawJson) as StoredVerdict;
        return {
            notice: parsed.notice ?? null,
            issuedAt: typeof parsed.issuedAt === 'number' ? parsed.issuedAt : 0,
            dismissed: Array.isArray(parsed.dismissed) ? parsed.dismissed : [],
        };
    } catch {
        return { notice: null, issuedAt: 0, dismissed: [] };
    }
}

async function saveVerdict(v: StoredVerdict): Promise<void> {
    await SecureStore.setItemAsync(STORE_KEY, JSON.stringify(v)).catch(() => undefined);
}

/** Remember that the user dismissed this notice. Only `recommended` is dismissible. */
export async function dismissNotice(id: string): Promise<void> {
    const stored = await loadVerdict();
    if (stored.dismissed.includes(id)) return;
    await saveVerdict({ ...stored, dismissed: [...stored.dismissed, id].slice(-20) });
}

/**
 * Decide whether to show an update notice, and which.
 *
 * Refreshes from the network, but the answer does not depend on that call
 * succeeding: a `required` verdict already recorded stands until a newer
 * manifest lifts it. Offline is not an escape hatch, because an attacker able
 * to keep a wallet on a vulnerable version would otherwise only need to drop a
 * request.
 *
 * @param language the app's current BCP-47 tag, for the server-supplied prose.
 */
export async function checkForUpdate(language: string): Promise<UpdateNotice | null> {
    const stored = await loadVerdict();
    const fresh = await fetchManifest(language, stored.issuedAt);
    const effective = fresh ?? { notice: stored.notice, issuedAt: stored.issuedAt };

    if (fresh) {
        await saveVerdict({ ...stored, notice: fresh.notice, issuedAt: fresh.issuedAt });
    }

    const notice = effective.notice;
    if (!notice) return null;
    // A dismissal is honoured only for a notice the user is ALLOWED to dismiss.
    // Re-reading it from the store on every check means a `recommended` notice
    // later escalated to `required` reappears, which is the point of escalating.
    if (notice.level === 'recommended' && stored.dismissed.includes(notice.id)) return null;
    return notice;
}

/**
 * Fetch and parse, or null when the document is unreachable, unreadable, or
 * older than the one already seen.
 *
 * The staleness check is the cheap half of the rollback defence: replaying a
 * captured older manifest cannot lower a floor. It does not stop suppression,
 * which is why the stored verdict survives a failed fetch.
 */
async function fetchManifest(
    language: string,
    knownIssuedAt: number,
): Promise<{ notice: UpdateNotice | null; issuedAt: number } | null> {
    try {
        const res = await withTimeout(
            fetch(MANIFEST_URL, { credentials: 'omit' }),
            FETCH_TIMEOUT_MS,
            'version manifest',
        );
        if (!res.ok) return null;
        // Signature first: nothing below this line looks at unverified content.
        const text = openEnvelope(await res.json());
        if (!text) return null;
        const parsed = parseManifest(JSON.parse(text), {
            platform: Platform.OS,
            version: currentVersion(),
            language,
        });
        if (!parsed) return null;
        if (parsed.issuedAt < knownIssuedAt) {
            console.warn('[version] ignoring a manifest older than the one already seen');
            return null;
        }
        return parsed;
    } catch (e) {
        console.warn('[version] could not read the version manifest:', e instanceof Error ? e.message : e);
        return null;
    }
}

/** Where to send someone who taps Update. */
export function storeUrl(): string {
    return Platform.OS === 'ios'
        ? 'https://apps.apple.com/app/id6761209489'
        : 'https://play.google.com/store/apps/details?id=org.privasys.wallet';
}
