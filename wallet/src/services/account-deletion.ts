// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Deleting the holder's Privasys account: the wallet's part.
 *
 * The flow itself is a page at privasys.id (account/delete). privasys.id keeps
 * no link between the holder's identities, or between an identity and the main
 * account, so only this wallet can name them all: once the holder confirms (the
 * page's confirm link opens the wallet), the wallet marks every identity in its
 * registry itself, each with a request signed by that identity's recovery key.
 * Cancelling works the same way, from the wallet only.
 *
 * Marks still to send are kept in an outbox and retried on every start until
 * each identity has answered, because an identity that is never marked simply
 * survives the deletion.
 *
 * The account (or this device, removed from another one) being gone is only
 * ever believed from privasys.id's tombstone answer, 410, never from a push:
 * a forged or replayed push cannot clear a wallet.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

import { currentLocale } from '@/i18n';
import { localRegistry } from '@/services/devices';
import { deriveRecoveryKey, epochCandidates, identityChallenge } from '@/services/identities';
import { ensurePrivasysSession } from '@/services/privasys-id';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
/** The page the holder deletes their account from. */
export const DELETE_PAGE_URL = `${IDP_BASE}/account/delete`;

const STATE_KEY = 'privasys.account-deletion.state';
const OUTBOX_KEY = 'privasys.account-deletion.outbox';
const MESSAGE_INFO = 'privasys-account-deletion/v1';

export type DeletionAction = 'schedule' | 'cancel';

/** A refusal from privasys.id, with its status: 404 an expired request, 409 blocked. */
export class DeletionError extends Error {
    constructor(
        readonly status: number,
        message: string,
    ) {
        super(message);
    }
}

/** What this wallet knows of a pending deletion, for the banner. */
export type DeletionState = { state: 'none' } | { state: 'pending'; deleteAt: string | null; pageUrl: string };

interface Outbox {
    action: DeletionAction;
    /**
     * schedule: the exact string privasys.id returned, signed as is, never
     * re-formatted. cancel: always empty; a cancel removes any mark on the
     * identity, whatever its date, so a device that never saw the date (a
     * cancel from another device, a phrase recovery) can still send it.
     */
    deleteAt: string;
    /** Identities (user handles) still to answer. */
    pending: string[];
}

const utf8 = (s: string) => new TextEncoder().encode(s);

/**
 * The bytes an identity's recovery key signs:
 *   "privasys-account-deletion/v1" 0 user_id 0 || challenge (raw) || 0 action 0 delete_at
 * The same layout as the identity revoke message, with the action and date.
 */
export function deletionMessage(userId: string, challenge: Uint8Array, action: DeletionAction, deleteAt: string): Uint8Array {
    const head = utf8(`${MESSAGE_INFO}\x00${userId}\x00`);
    const tail = utf8(`\x00${action}\x00${deleteAt}`);
    const out = new Uint8Array(head.length + challenge.length + tail.length);
    out.set(head, 0);
    out.set(challenge, head.length);
    out.set(tail, head.length + challenge.length);
    return out;
}

async function idp<T>(path: string, init: RequestInit = {}): Promise<{ status: number; body: T | null }> {
    const res = await fetch(`${IDP_BASE}${path}`, init);
    let body: T | null = null;
    try {
        body = (await res.json()) as T;
    } catch {
        body = null;
    }
    return { status: res.status, body };
}

const headers = (session?: string): HeadersInit => ({
    'Content-Type': 'application/json',
    ...(session ? { Authorization: `Bearer wallet:${session}` } : {}),
});

/** A deletion date the way the holder reads dates, e.g. "28 November 2026". */
export function deletionDate(at: Date): string {
    try {
        return at.toLocaleDateString(currentLocale(), { day: 'numeric', month: 'long', year: 'numeric' });
    } catch {
        return at.toDateString();
    }
}

// ---------------------------------------------------------------- state

export async function loadDeletionState(): Promise<DeletionState> {
    try {
        const raw = await SecureStore.getItemAsync(STATE_KEY);
        if (raw) {
            const s = JSON.parse(raw) as DeletionState;
            if (s.state === 'pending' || s.state === 'none') return s;
        }
    } catch {
        /* unreadable: none */
    }
    return { state: 'none' };
}

async function saveDeletionState(s: DeletionState): Promise<void> {
    if (s.state === 'none') await SecureStore.deleteItemAsync(STATE_KEY);
    else await SecureStore.setItemAsync(STATE_KEY, JSON.stringify(s));
    for (const l of listeners) l(s);
}

const listeners = new Set<(s: DeletionState) => void>();
/** Hear of changes to the pending deletion (the banner). Returns the unsubscribe. */
export function onDeletionState(l: (s: DeletionState) => void): () => void {
    listeners.add(l);
    return () => listeners.delete(l);
}

/**
 * Ask privasys.id whether a deletion is pending, with the session this wallet
 * already holds: never a sign-in prompt just to draw a banner. A push without a
 * session to check it with still shows the banner, without its date.
 */
export async function refreshDeletionState(hint?: 'pending' | 'none'): Promise<DeletionState> {
    const slot = useAuthStore.getState().privasysId;
    const session = slot?.sessionToken && Date.now() < slot.sessionExpiresAt ? slot.sessionToken : null;
    if (session) {
        try {
            const r = await idp<{ state?: string; delete_at?: string; page_url?: string }>('/account-deletion', {
                headers: headers(session),
            });
            if (r.status === 200 && r.body?.state) {
                const s: DeletionState =
                    r.body.state === 'pending'
                        ? { state: 'pending', deleteAt: r.body.delete_at ?? null, pageUrl: r.body.page_url ?? DELETE_PAGE_URL }
                        : { state: 'none' };
                await saveDeletionState(s);
                return s;
            }
        } catch {
            /* offline: what we knew */
        }
    }
    if (hint === 'pending') {
        const known = await loadDeletionState();
        const s: DeletionState = known.state === 'pending' ? known : { state: 'pending', deleteAt: null, pageUrl: DELETE_PAGE_URL };
        await saveDeletionState(s);
        return s;
    }
    if (hint === 'none') {
        await saveDeletionState({ state: 'none' });
        return { state: 'none' };
    }
    return loadDeletionState();
}

// ---------------------------------------------------------------- the main account

/**
 * A main-account session from a sign-in just now. privasys.id wants one under
 * five minutes old to confirm or cancel a deletion, and the biometric prompt
 * the sign-in brings is the holder's confirmation, so a cached session is
 * never reused here.
 */
async function freshSession(): Promise<string> {
    const store = useAuthStore.getState();
    const slot = store.privasysId;
    if (slot?.sessionToken) store.setPrivasysId({ ...slot, sessionToken: '', sessionExpiresAt: 0 });
    return (await ensurePrivasysSession()).sessionToken;
}

/**
 * The holder confirmed the deletion the page asked for (its confirm link).
 * Signs in afresh, registers it, then marks every identity. Returns delete_at.
 */
export async function confirmDeletion(requestId: string): Promise<string> {
    const session = await freshSession();
    const r = await idp<{ delete_at?: string; error?: string }>('/account-deletion', {
        method: 'POST',
        headers: headers(session),
        body: JSON.stringify({ request_id: requestId }),
    });
    if (r.status !== 200 || !r.body?.delete_at) {
        throw new DeletionError(r.status, r.body?.error ?? `the deletion could not be confirmed (HTTP ${r.status})`);
    }
    const deleteAt = r.body.delete_at;
    await saveDeletionState({ state: 'pending', deleteAt, pageUrl: DELETE_PAGE_URL });
    await queue('schedule', deleteAt);
    await flushDeletionOutbox();
    return deleteAt;
}

/** The holder cancels from the banner: the main account, then every identity. */
export async function cancelDeletion(): Promise<void> {
    const session = await freshSession();
    const r = await idp<{ error?: string }>('/account-deletion', { method: 'DELETE', headers: headers(session) });
    if (r.status !== 200) {
        throw new Error(r.body?.error ?? `the deletion could not be cancelled (HTTP ${r.status})`);
    }
    await saveDeletionState({ state: 'none' });
    await queue('cancel', '');
    await flushDeletionOutbox();
}

/**
 * The deletion was cancelled elsewhere (another device), or a phrase recovery
 * cancelled the main account's mark: unmark every identity this wallet holds.
 */
export async function cancelIdentityMarks(): Promise<void> {
    await saveDeletionState({ state: 'none' });
    await queue('cancel', '');
    await flushDeletionOutbox();
}

// ---------------------------------------------------------------- identities

async function queue(action: DeletionAction, deleteAt: string): Promise<void> {
    const reg = await localRegistry();
    const pending = [...new Set(reg.identities.map((i) => i.userHandle))];
    // A newer action replaces an older one: a cancel after a schedule only
    // needs the cancels.
    await SecureStore.setItemAsync(OUTBOX_KEY, JSON.stringify({ action, deleteAt, pending } satisfies Outbox));
}

async function loadOutbox(): Promise<Outbox | null> {
    try {
        const raw = await SecureStore.getItemAsync(OUTBOX_KEY);
        return raw ? (JSON.parse(raw) as Outbox) : null;
    } catch {
        return null;
    }
}

/** How many identities are still to be marked or unmarked. */
export async function pendingIdentityCount(): Promise<number> {
    return (await loadOutbox())?.pending.length ?? 0;
}

let flushing: Promise<number> | null = null;

/**
 * Send every mark still waiting. Each identity is signed by its recovery key,
 * trying each epoch the key may be on (a wrong one answers 403). Returns how
 * many are still waiting. Safe to call at any time; runs once at a time.
 */
export function flushDeletionOutbox(): Promise<number> {
    if (flushing) return flushing;
    flushing = (async () => {
        const box = await loadOutbox();
        if (!box || box.pending.length === 0) {
            await SecureStore.deleteItemAsync(OUTBOX_KEY);
            return 0;
        }
        const seed = useProfileStore.getState().profile?.pairwiseSeed;
        if (!seed) return box.pending.length;
        const left: string[] = [];
        for (const userId of box.pending) {
            let done = false;
            try {
                done = await markIdentity(seed, userId, box.action, box.deleteAt);
            } catch (e: any) {
                console.warn('[account-deletion] an identity is still to be marked:', e?.message ?? e);
            }
            if (!done) left.push(userId);
        }
        if (left.length === 0) await SecureStore.deleteItemAsync(OUTBOX_KEY);
        else await SecureStore.setItemAsync(OUTBOX_KEY, JSON.stringify({ ...box, pending: left } satisfies Outbox));
        return left.length;
    })().finally(() => {
        flushing = null;
    });
    return flushing;
}

async function markIdentity(seed: string, userId: string, action: DeletionAction, deleteAt: string): Promise<boolean> {
    for (const epoch of await epochCandidates(userId)) {
        const challengeB64 = await identityChallenge(userId);
        const { secretKey } = deriveRecoveryKey(seed, userId, epoch);
        const msg = deletionMessage(userId, base64urlToBytes(challengeB64), action, deleteAt);
        const r = await idp<{ error?: string }>('/account-deletion/identity', {
            method: 'POST',
            headers: headers(),
            body: JSON.stringify({
                user_id: userId,
                action,
                delete_at: deleteAt,
                challenge: challengeB64,
                signature: bytesToBase64url(ed25519.sign(msg, secretKey)),
            }),
        });
        // 200: done, whether or not it was already in that state.
        if (r.status === 200) return true;
        // 403: signed with another epoch's key: try the next one. Anything else
        // (400, a 5xx) leaves it in the outbox for the next attempt.
        if (r.status !== 403) throw new Error(r.body?.error ?? `HTTP ${r.status}`);
    }
    return false;
}

// ---------------------------------------------------------------- gone

export type GoneReason = 'account_deleted' | 'device_removed';

/**
 * Whether privasys.id says this wallet's account was deleted, or this device
 * removed from it. Only a 410 with one of those reasons counts; anything else,
 * offline included, is "not gone".
 */
export async function checkGone(): Promise<GoneReason | null> {
    const credentialId = useAuthStore.getState().privasysId?.credentialId;
    if (!credentialId) return null;
    try {
        const r = await idp<{ error?: string }>(
            `/account-deletion/tombstone?credential_id=${encodeURIComponent(credentialId)}`,
        );
        if (r.status === 410 && (r.body?.error === 'account_deleted' || r.body?.error === 'device_removed')) {
            return r.body.error;
        }
    } catch {
        /* offline */
    }
    return null;
}

/** Part of Clear All Data. */
export async function clearAccountDeletionLocalState(): Promise<void> {
    await SecureStore.deleteItemAsync(STATE_KEY);
    await SecureStore.deleteItemAsync(OUTBOX_KEY);
}
