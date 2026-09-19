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
 * - Keyed by the service's ATTESTED app id and the capability kind. Never by
 *   a name or a host, which a request could choose to collide with another
 *   service's.
 * - Secrets are never prefilled into a form. When a service refuses what was
 *   kept (the password was changed at the provider) the holder types the
 *   secret again; only the non-secret answers (the address) come back.
 * - Forgotten when the LAST capability over that (service, kind) is revoked,
 *   at the same moment the service destroys its own copy. A credential kept
 *   after nothing is approved to use it is a credential nobody authorised.
 *
 * Not part of the phrase-wrapped backup, deliberately: a recovered phone asks
 * for the password once more, which is one form, and a password in a backup
 * is one more place a password exists.
 */

import * as SecureStore from '@/utils/storage';

const PREFIX = 'v1-setup-keep:';
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

export function keepKey(serviceAppId: string, kind: string): string {
    return `${PREFIX}${normaliseId(serviceAppId)}:${kind}`;
}

export interface KeptSetup {
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

/** Keep what a successful mint sent. Replaces whatever was kept before. */
export async function keepSetup(args: {
    serviceAppId: string;
    kind: string;
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
        answers,
        secrets: args.secrets,
        secretLabels: args.secretLabels,
        label: labelOf(answers, args.secrets),
        kept: args.kept,
        keptAt: args.now ?? Math.floor(Date.now() / 1000),
    };
    const key = keepKey(args.serviceAppId, args.kind);
    await SecureStore.setItemAsync(key, JSON.stringify(value));
    const index = await readIndex();
    if (!index.includes(key)) await writeIndex([...index, key]);
}

/** What this phone kept for a service and kind, or null. */
export async function keptSetup(serviceAppId: string, kind: string): Promise<KeptSetup | null> {
    let raw: string | null;
    try {
        raw = await SecureStore.getItemAsync(keepKey(serviceAppId, kind));
    } catch {
        return null;
    }
    if (!raw) return null;
    try {
        const v = JSON.parse(raw) as KeptSetup;
        if (!v || typeof v !== 'object' || !v.answers || typeof v.answers !== 'object') return null;
        return {
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

export async function forgetSetup(serviceAppId: string, kind: string): Promise<void> {
    const key = keepKey(serviceAppId, kind);
    await SecureStore.deleteItemAsync(key).catch(() => undefined);
    const index = await readIndex();
    if (index.includes(key)) await writeIndex(index.filter((k) => k !== key));
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
