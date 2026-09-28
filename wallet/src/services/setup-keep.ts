// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the holder typed for a service, kept on this phone so they are not
 * asked again.
 *
 * A resource service that needs a credential (a mailbox password, later an
 * OAuth grant) keeps nothing at rest: it holds the value in the memory of its
 * enclave and forgets it when it restarts. The one durable copy is here, in
 * the device's secure store, where the platform keeps every other piece of
 * the holder's data. On the next ask for the same service and kind the wallet
 * sends what it kept with the mint, on the holder's tap, and the service is
 * connected again without a form.
 *
 * Three rules, each the reason for a line below:
 *
 * - Keyed by the service's ATTESTED app id, the capability kind and the
 *   account the service said was connected (a holder may connect a personal
 *   and a work mailbox to one service). Never by a name or a host, which a
 *   request could choose to collide with another service's.
 * - Secrets are never prefilled into a form. When a service refuses what was
 *   kept (the password was changed at the provider) the holder types the
 *   secret again; only the non-secret answers (the address) come back.
 * - Forgotten when the LAST capability over that account is revoked,
 *   at the same moment the service destroys its own copy. A credential kept
 *   after nothing is approved to use it is a credential nobody authorised.
 *
 * Not part of the phrase-wrapped backup, deliberately: a recovered phone asks
 * for the password once more, which is one form, and a password in a backup
 * is one more place a password exists.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import * as SecureStore from '@/utils/storage';

/**
 * The secure store takes keys of letters, digits, ".", "-" and "_" only, and
 * throws on anything else. v1 keys carried ":", so on a phone nothing was ever
 * kept under them; v2 is the first spelling the store accepts.
 */
const PREFIX = 'v2-setup-keep.';
/**
 * The secure store cannot be listed, so the keys in use are kept under one
 * more, for the wipe: a new identity on this device must not inherit the
 * last one's passwords.
 */
const INDEX_KEY = 'v1-setup-keep-index';

async function readIndex(): Promise<string[]> {
    try {
        const raw = await SecureStore.getItemAsync(INDEX_KEY);
        const list = raw ? (JSON.parse(raw) as unknown) : [];
        return Array.isArray(list) ? list.filter((k): k is string => typeof k === 'string') : [];
    } catch {
        return [];
    }
}

async function writeIndex(keys: string[]): Promise<void> {
    if (keys.length === 0) {
        await SecureStore.deleteItemAsync(INDEX_KEY).catch(() => undefined);
        return;
    }
    await SecureStore.setItemAsync(INDEX_KEY, JSON.stringify(keys));
}

/** One spelling per app id, so a dashed and a bare id are the same service. */
function normaliseId(appId: string): string {
    const hex = appId.trim().toLowerCase().replace(/-/g, '');
    if (!/^[0-9a-f]{32}$/.test(hex)) {
        throw new Error('setup keep: not an app id');
    }
    return hex;
}

/** An account as the connectors compare it: trimmed, lower case. */
export function normaliseAccount(account: string | undefined): string {
    return (account ?? '').trim().toLowerCase();
}

/** The part of a key that is one (service, kind), every account under it. */
function serviceKindPrefix(serviceAppId: string, kind: string): string {
    if (!/^[\w.-]+$/.test(kind)) throw new Error('setup keep: not a capability kind');
    return `${PREFIX}${normaliseId(serviceAppId)}.${kind}.`;
}

/**
 * Where one account's details are kept. The account is hashed into the key,
 * since an address is not a spelling the store accepts; the account itself is
 * inside the value. "" is a service that names no account.
 */
export function keepKey(serviceAppId: string, kind: string, account?: string): string {
    const a = normaliseAccount(account);
    const tag = a ? bytesToHex(sha256(new TextEncoder().encode(a))).slice(0, 32) : 'none';
    return `${serviceKindPrefix(serviceAppId, kind)}${tag}`;
}

export interface KeptSetup {
    /**
     * The account the service said this connected (`service_result.account`),
     * normalised, or "" for a service that names none.
     */
    account: string;
    /** Everything sent as `setup` with the mint that succeeded. */
    answers: Record<string, unknown>;
    /** The names of the answers that were secrets. Never prefilled. */
    secrets: string[];
    /**
     * The service's own labels for those secrets ("App password"), so the
     * Access row can still say what was handed over when the answers were
     * re-supplied rather than typed.
     */
    secretLabels?: string[];
    /**
     * The first non-secret string answer (an address), so a screen can say
     * "your saved details for alice@example.org" without reading a secret.
     */
    label?: string;
    /**
     * Opaque values the service asked the wallet to hold for it (`keep` on
     * the mint response): a refresh token it exchanged and does not store.
     * Sent back as `setup.kept` on the next mint, never read here.
     */
    kept?: Record<string, unknown>;
    /** Epoch seconds. */
    keptAt: number;
}

/** The first non-secret string answer, trimmed, or nothing. */
export function labelOf(answers: Record<string, unknown>, secrets: string[]): string | undefined {
    for (const [name, value] of Object.entries(answers)) {
        if (secrets.includes(name)) continue;
        if (typeof value === 'string' && value.trim()) return value.trim().slice(0, 120);
    }
    return undefined;
}

/**
 * Keep what a successful mint sent. Replaces whatever was kept before for the
 * same account.
 */
export async function keepSetup(args: {
    serviceAppId: string;
    kind: string;
    /** The account the service said was connected; "" or absent for none. */
    account?: string;
    answers: Record<string, unknown>;
    secrets: string[];
    secretLabels?: string[];
    kept?: Record<string, unknown>;
    now?: number;
}): Promise<void> {
    // `kept` is the service's, carried separately; it never sits among the
    // holder's answers where a later form could show it.
    const { kept: _dropped, ...answers } = args.answers;
    void _dropped;
    const value: KeptSetup = {
        account: normaliseAccount(args.account),
        answers,
        secrets: args.secrets,
        secretLabels: args.secretLabels,
        label: labelOf(answers, args.secrets),
        kept: args.kept,
        keptAt: args.now ?? Math.floor(Date.now() / 1000),
    };
    const key = keepKey(args.serviceAppId, args.kind, args.account);
    await SecureStore.setItemAsync(key, JSON.stringify(value));
    const index = await readIndex();
    if (!index.includes(key)) await writeIndex([...index, key]);
}

async function readKept(key: string): Promise<KeptSetup | null> {
    let raw: string | null;
    try {
        raw = await SecureStore.getItemAsync(key);
    } catch {
        return null;
    }
    if (!raw) return null;
    try {
        const v = JSON.parse(raw) as KeptSetup;
        if (!v || typeof v !== 'object' || !v.answers || typeof v.answers !== 'object') return null;
        return {
            account: typeof v.account === 'string' ? v.account : '',
            answers: v.answers,
            secrets: Array.isArray(v.secrets) ? v.secrets.filter((s): s is string => typeof s === 'string') : [],
            secretLabels: Array.isArray(v.secretLabels)
                ? v.secretLabels.filter((s): s is string => typeof s === 'string')
                : undefined,
            label: typeof v.label === 'string' ? v.label : undefined,
            kept: v.kept && typeof v.kept === 'object' ? v.kept : undefined,
            keptAt: typeof v.keptAt === 'number' ? v.keptAt : 0,
        };
    } catch {
        return null;
    }
}

/**
 * Every account this phone kept details for at a service and kind, the most
 * recently kept first.
 */
export async function keptSetups(serviceAppId: string, kind: string): Promise<KeptSetup[]> {
    const prefix = serviceKindPrefix(serviceAppId, kind);
    const keys = (await readIndex()).filter((k) => k.startsWith(prefix));
    const all = await Promise.all(keys.map(readKept));
    return all.filter((k): k is KeptSetup => k !== null).sort((a, b) => b.keptAt - a.keptAt);
}

/**
 * What this phone kept for one account at a service and kind, or null. With
 * no account named, the one most recently kept.
 */
export async function keptSetup(serviceAppId: string, kind: string, account?: string): Promise<KeptSetup | null> {
    if (account !== undefined) return readKept(keepKey(serviceAppId, kind, account));
    return (await keptSetups(serviceAppId, kind))[0] ?? null;
}

/**
 * Forget one account's details at a service and kind, or, with no account
 * named, every account's.
 */
export async function forgetSetup(serviceAppId: string, kind: string, account?: string): Promise<void> {
    const index = await readIndex();
    const doomed =
        account !== undefined
            ? [keepKey(serviceAppId, kind, account)]
            : index.filter((k) => k.startsWith(serviceKindPrefix(serviceAppId, kind)));
    await Promise.all(doomed.map((k) => SecureStore.deleteItemAsync(k).catch(() => undefined)));
    const left = index.filter((k) => !doomed.includes(k));
    if (left.length !== index.length) await writeIndex(left);
}

/** Everything kept, for the wipe. */
export async function clearKeptSetups(): Promise<void> {
    const index = await readIndex();
    await Promise.all(index.map((k) => SecureStore.deleteItemAsync(k).catch(() => undefined)));
    await writeIndex([]);
}

/**
 * The `setup` to send on a re-supply: the kept answers, plus the service's
 * own kept values under `kept`. The service reads the answers it named and
 * ignores the rest, so a service that kept nothing sees exactly what it saw
 * the first time.
 */
export function resupplyPayload(k: KeptSetup): Record<string, unknown> {
    return k.kept ? { ...k.answers, kept: k.kept } : { ...k.answers };
}

/**
 * Starting values for a form shown after a re-supply was refused: what was
 * kept, minus every secret. The holder types the secret again.
 */
export function nonSecretAnswers(k: KeptSetup): Record<string, string | boolean> {
    const out: Record<string, string | boolean> = {};
    for (const [name, value] of Object.entries(k.answers)) {
        if (k.secrets.includes(name) || name === 'kept') continue;
        if (typeof value === 'string' || typeof value === 'boolean') out[name] = value;
    }
    return out;
}
