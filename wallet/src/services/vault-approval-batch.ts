// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One approval for a list of vault operations: what the wallet checks before it
 * shows the list.
 *
 * The WebAuthn challenge of a batch IS a hash of the list. The identity provider
 * sends the list and the challenge separately, so nothing but this check ties
 * the rows on screen to what the passkey signs. Every value is recomputed here,
 * and anything that does not hash to the challenge is refused before the holder
 * sees a row:
 *
 *   vault_op_i = b64url(SHA-256("privasys-vault-approval/v1\n" handle "\n"
 *                measurement_digest "\n" policy_version "\n" nonce "\n" exp))
 *   batch_id   = b64url(SHA-256("privasys-vault-approval-batch-v1\n" label "\n"
 *                exp "\n" count ("\n" operation " " vault_op_i)...))
 *
 * Pinned against the identity provider by shared/vault-approval-batch-vectors.json.
 *
 * Each entry's `context` is written by whoever began the batch and is bound by
 * nothing, so it is dropped here: a verified batch cannot carry it to the screen.
 * One field survives, as a question rather than an answer: a promote's
 * version id, which the card asks the control plane about (versionIdHint).
 * This module has no native imports, so all of it runs under test.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { bindingVaultOp, deleteAfterTarget, type VaultOp } from './vault-binding';
import { checkMembers, policyDigest, type VaultIdentity } from './vault-identity';

const BATCH_DOMAIN = 'privasys-vault-approval-batch-v1';
const SINGLE_DOMAIN = 'privasys-vault-approval/v1';

export const VAULT_BATCH_MAX_ENTRIES = 32;
/** A control-plane version id: the only form of entry context the card keeps. */
const VERSION_ID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const MAX_LABEL_CHARS = 120;
const MAX_HANDLE_BYTES = 512;

/** Only these may share one approval: an export, a key-policy change or a
 *  recovery releases or changes control of a key, and stays one approval each. */
const BATCHABLE = new Set(['promote', 'app-policy']);
/** In a batch of binding v2 entries. A delete_after is the old key of a migrate
 *  or upgrade, accepted only beside its successor's promote. */
const BATCHABLE_V2 = new Set(['promote', 'update_policy', 'revoke_pending', 'delete_after']);
/** A delete_after beside its successor's promote may outlive its batch by this
 *  much at most: it waits for the migrate or upgrade to succeed. */
const DELETE_AFTER_MAX_SECONDS = 86400;
/** One that names a created successor waits for nothing (that key exists
 *  already), so it gets no more than an ordinary approval's lifetime. */
const DELETE_AFTER_CREATED_MAX_SECONDS = 600;

const DIGEST_HEX = /^[0-9a-f]{64}$/;
const BATCH_ID = /^[A-Za-z0-9_-]{43}$/;
const NONCE = /^[A-Za-z0-9_-]+$/;
const APP_ID_HEX = /^[0-9a-f]{32}$/;

/** Characters that change how text reads without being seen: controls, format
 *  and bidirectional marks, and line separators. */
// oxlint-disable-next-line no-control-regex -- matching them is the point
const HIDDEN = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/;
/** A lone surrogate encodes as U+FFFD, so two different strings could hash alike. */
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?:[^\ud800-\udbff]|^)[\udc00-\udfff]/;

export type VaultBatchRefusal =
    /** The answer is not the shape the contract describes. */
    | 'malformed'
    /** An operation that may not be batched. */
    | 'operation'
    /** The list is not in canonical order, or names an entry twice. */
    | 'order'
    /** An entry does not hash to its vault_op. */
    | 'entry'
    /** The list does not hash to the batch id. */
    | 'binding'
    /** The passkey would sign something other than this list. */
    | 'challenge';

export class VaultBatchRefused extends Error {
    constructor(readonly reason: VaultBatchRefusal) {
        super(`vault batch refused: ${reason}`);
        this.name = 'VaultBatchRefused';
    }
}

export interface VerifiedVaultBatchEntry {
    operation: 'promote' | 'app-policy' | 'update_policy' | 'revoke_pending' | 'delete_after';
    /** A binding v2 entry: when its own approval expires (a delete_after
     *  outlives the batch), and for a policy update the policy it installs. */
    v2?: { exp: number; newPolicy?: unknown; successor?: string };
    handle: string;
    measurementDigest: string;
    policyVersion: number;
    vaultOp: string;
    /**
     * The app version the initiator says this promote is for. Bound by
     * nothing, so it is never shown: it is only the question the card asks the
     * control plane, which answers for the app named in the signed handle and
     * refuses a version of any other app.
     */
    versionIdHint?: string;
}

export interface VerifiedVaultBatch {
    batchId: string;
    /** Bound by the signature, but written by whoever began the batch. */
    label: string;
    exp: number;
    entries: VerifiedVaultBatchEntry[];
    /** A v2 batch: the builds the vaults it names claim (distinct, hex). The
     *  card names them as a published release before it offers Approve. */
    builds?: string[];
    /** A v2 batch: those vaults' billing ids (distinct), which say the platform. */
    billingIds?: string[];
    options: {
        publicKey: {
            /** Always the recomputed binding, never the server's copy. */
            challenge: string;
            rpId?: string;
            allowCredentials?: Array<{ type: string; id: string }>;
        };
    };
}

const utf8 = (s: string) => new TextEncoder().encode(s);

function base64url(bytes: Uint8Array): string {
    const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let out = '';
    for (let i = 0; i < bytes.length; i += 3) {
        const a = bytes[i];
        const b = bytes[i + 1];
        const c = bytes[i + 2];
        out += abc[a >> 2] + abc[((a & 3) << 4) | ((b ?? 0) >> 4)];
        if (b !== undefined) out += abc[((b & 15) << 2) | ((c ?? 0) >> 6)];
        if (c !== undefined) out += abc[c & 63];
    }
    return out;
}

/** The binding of one operation, as the vault recomputes it. */
export function computeVaultOp(
    handle: string,
    measurementDigest: string,
    policyVersion: number,
    nonce: string,
    exp: number,
): string {
    const input = [SINGLE_DOMAIN, handle, measurementDigest, policyVersion, nonce, exp].join('\n');
    return base64url(sha256(utf8(input)));
}

/** The binding of the whole list: the batch id, and the WebAuthn challenge. */
export function computeVaultBatchId(
    label: string,
    exp: number,
    entries: ReadonlyArray<{ operation: string; vaultOp: string }>,
): string {
    const lines = [BATCH_DOMAIN, label, String(exp), String(entries.length)];
    for (const e of entries) lines.push(`${e.operation} ${e.vaultOp}`);
    return base64url(sha256(utf8(lines.join('\n'))));
}

/** Byte order of the UTF-8 text, which is how the identity provider sorts.
 *  JavaScript's own `<` compares UTF-16 units and disagrees above U+FFFF. */
function compareUtf8(a: string, b: string): number {
    const x = utf8(a);
    const y = utf8(b);
    const n = Math.min(x.length, y.length);
    for (let i = 0; i < n; i++) {
        if (x[i] !== y[i]) return x[i] - y[i];
    }
    return x.length - y.length;
}

const isText = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

function validLabel(label: unknown): label is string {
    return (
        isText(label) &&
        label === label.trim() &&
        Array.from(label).length <= MAX_LABEL_CHARS &&
        !HIDDEN.test(label) &&
        !LONE_SURROGATE.test(label)
    );
}

function validHandle(handle: unknown): handle is string {
    return (
        isText(handle) &&
        utf8(handle).length <= MAX_HANDLE_BYTES &&
        !/\s/.test(handle) &&
        !HIDDEN.test(handle) &&
        !LONE_SURROGATE.test(handle)
    );
}

/** Whether a string can be a batch id at all, before it is sent anywhere. */
export function isVaultBatchId(id: string): boolean {
    return BATCH_ID.test(id);
}

/**
 * One binding v2 entry: its binding rebuilt from its fields must be its
 * vault_op, its own fields must be the binding's, every vault it names must
 * have an identity that agrees with itself, and a policy update must be bound
 * to the policy it carries.
 */
function verifyV2Entry(
    e: Record<string, unknown>,
    batchExp: number,
    identities: unknown,
): { entry: VerifiedVaultBatchEntry; builds: string[]; billingIds: string[] } {
    if (typeof e.operation !== 'string' || !BATCHABLE_V2.has(e.operation)) throw new VaultBatchRefused('operation');
    const b = (e.binding ?? {}) as Record<string, unknown>;
    const { handle, vault_op: vaultOp } = e;
    const target = b.target === '-' ? '' : b.target;
    if (
        !validHandle(handle) ||
        typeof vaultOp !== 'string' ||
        typeof target !== 'string' ||
        !DIGEST_HEX.test(target) ||
        !Number.isSafeInteger(b.policy_version) ||
        (b.policy_version as number) < 0 ||
        !Number.isSafeInteger(b.exp) ||
        typeof b.nonce !== 'string' ||
        typeof b.approver !== 'string' ||
        !/^oidc:\d+:.+$/.test(b.approver) ||
        b.holder_head !== '-' ||
        !Array.isArray(b.members)
    ) {
        throw new VaultBatchRefused('malformed');
    }
    // The entry's own fields are the binding's.
    if (
        b.op !== e.operation ||
        b.handle !== handle ||
        e.policy_version !== b.policy_version ||
        e.nonce !== b.nonce ||
        (e.measurement_digest ?? '') !== target
    ) {
        throw new VaultBatchRefused('entry');
    }
    // Every entry expires with the batch, except the old key's delete, which
    // is held until the migrate or upgrade has succeeded.
    const entryExp = b.exp as number;
    const namesSuccessor = e.successor_handle !== undefined && e.successor_handle !== null && e.successor_handle !== '';
    if (e.operation === 'delete_after') {
        const most = namesSuccessor ? DELETE_AFTER_CREATED_MAX_SECONDS : DELETE_AFTER_MAX_SECONDS;
        if (entryExp < batchExp || entryExp > batchExp + most) throw new VaultBatchRefused('entry');
    } else if (entryExp !== batchExp) {
        throw new VaultBatchRefused('entry');
    }
    let rebuilt: string;
    try {
        rebuilt = bindingVaultOp({
            members: b.members as string[],
            op: e.operation as VaultOp,
            handle,
            target,
            policyVersion: b.policy_version as number,
            approver: b.approver,
            nonce: b.nonce,
            exp: entryExp,
        });
    } catch {
        throw new VaultBatchRefused('malformed');
    }
    if (rebuilt !== vaultOp) throw new VaultBatchRefused('entry');

    const members = checkMembers(b.members as string[], identities as VaultIdentity[] | undefined);
    if (!members) throw new VaultBatchRefused('entry');

    const hasPolicy = e.new_policy !== undefined && e.new_policy !== null;
    if (e.operation === 'update_policy') {
        let pd: string;
        try {
            pd = policyDigest(e.new_policy);
        } catch {
            throw new VaultBatchRefused('malformed');
        }
        if (pd !== target) throw new VaultBatchRefused('entry');
    } else if (hasPolicy) {
        throw new VaultBatchRefused('malformed');
    }
    // The delete of an old key may name a created successor instead of
    // standing beside a promote: its target must be that successor's.
    let successor: string | undefined;
    const named = e.successor_handle;
    if (namesSuccessor) {
        if (e.operation !== 'delete_after' || !validHandle(named) || named === handle) throw new VaultBatchRefused('malformed');
        if (deleteAfterTarget(named, '') !== target) throw new VaultBatchRefused('entry');
        successor = named;
    }
    const hint = ((e.context ?? {}) as Record<string, unknown>).version_id;
    return {
        builds: members.builds,
        billingIds: members.billingIds,
        entry: {
            operation: e.operation as VerifiedVaultBatchEntry['operation'],
            handle,
            measurementDigest: target,
            policyVersion: b.policy_version as number,
            vaultOp,
            v2: { exp: entryExp, ...(hasPolicy ? { newPolicy: e.new_policy } : {}), ...(successor ? { successor } : {}) },
            ...(e.operation === 'promote' && typeof hint === 'string' && VERSION_ID.test(hint)
                ? { versionIdHint: hint.toLowerCase() }
                : {}),
        },
    };
}

/**
 * Check a `batch/pending` answer against the batch id the wallet asked for.
 * Returns the list only when every value hashes to that id, and throws
 * `VaultBatchRefused` otherwise.
 */
export function verifyVaultBatch(requestedBatchId: string, answer: unknown): VerifiedVaultBatch {
    const a = (answer ?? {}) as Record<string, unknown>;
    const { label, exp, entries } = a;
    if (!isVaultBatchId(requestedBatchId) || a.batch_id !== requestedBatchId) {
        throw new VaultBatchRefused('binding');
    }
    if (!validLabel(label) || !Number.isSafeInteger(exp) || (exp as number) <= 0) {
        throw new VaultBatchRefused('malformed');
    }
    if (!Array.isArray(entries) || entries.length < 1 || entries.length > VAULT_BATCH_MAX_ENTRIES) {
        throw new VaultBatchRefused('malformed');
    }

    // A batch is all binding v2 or all v1: never a mix.
    const v2Count = entries.filter((e) => (e as Record<string, unknown> | null)?.binding != null).length;
    if (v2Count !== 0 && v2Count !== entries.length) throw new VaultBatchRefused('malformed');
    const isV2Batch = v2Count > 0;
    const builds = new Set<string>();
    const billingIds = new Set<string>();
    const successors = new Set<string>();

    const verified: VerifiedVaultBatchEntry[] = [];
    for (const raw of entries) {
        const e = (raw ?? {}) as Record<string, unknown>;
        if (isV2Batch) {
            const got = verifyV2Entry(e, exp as number, a.member_identities);
            for (const b of got.builds) builds.add(b);
            for (const b of got.billingIds) billingIds.add(b);
            if (got.entry.operation === 'promote') {
                successors.add(deleteAfterTarget(got.entry.handle, got.entry.measurementDigest));
            }
            verified.push(got.entry);
            continue;
        }
        if (typeof e.operation !== 'string' || !BATCHABLE.has(e.operation)) {
            throw new VaultBatchRefused('operation');
        }
        const { handle, measurement_digest: digest, policy_version: version, nonce, vault_op: vaultOp } = e;
        if (
            !validHandle(handle) ||
            typeof digest !== 'string' ||
            !DIGEST_HEX.test(digest) ||
            // Above 2^53 JSON has already rounded the number the vault will check.
            !Number.isSafeInteger(version) ||
            (version as number) < 0 ||
            typeof nonce !== 'string' ||
            !NONCE.test(nonce) ||
            typeof vaultOp !== 'string'
        ) {
            throw new VaultBatchRefused('malformed');
        }
        if (e.operation === 'app-policy' && !(handle.startsWith('app:') && handle.endsWith(':policy'))) {
            throw new VaultBatchRefused('malformed');
        }
        if (computeVaultOp(handle, digest, version as number, nonce, exp as number) !== vaultOp) {
            throw new VaultBatchRefused('entry');
        }
        const hint = ((e.context ?? {}) as Record<string, unknown>).version_id;
        verified.push({
            operation: e.operation as VerifiedVaultBatchEntry['operation'],
            handle,
            measurementDigest: digest,
            policyVersion: version as number,
            vaultOp,
            ...(e.operation === 'promote' && typeof hint === 'string' && VERSION_ID.test(hint)
                ? { versionIdHint: hint.toLowerCase() }
                : {}),
        });
    }

    // Never sorted here: a list out of order is refused, not repaired. Strictly
    // ascending, so the same entry cannot appear twice either.
    for (let i = 1; i < verified.length; i++) {
        const byHandle = compareUtf8(verified[i - 1].handle, verified[i].handle);
        const order = byHandle || compareUtf8(verified[i - 1].operation, verified[i].operation);
        if (order >= 0) throw new VaultBatchRefused('order');
    }

    // The old key's delete is approved only beside the promote of its successor.
    for (const v of verified) {
        if (v.operation === 'delete_after' && !v.v2?.successor && !successors.has(v.measurementDigest)) {
            throw new VaultBatchRefused('operation');
        }
    }

    const batchId = computeVaultBatchId(label, exp as number, verified);
    if (batchId !== requestedBatchId) throw new VaultBatchRefused('binding');

    const publicKey = ((a.options ?? {}) as { publicKey?: Record<string, unknown> }).publicKey;
    if (!publicKey || publicKey.challenge !== batchId) throw new VaultBatchRefused('challenge');

    return {
        batchId,
        label,
        exp: exp as number,
        entries: verified,
        ...(isV2Batch ? { builds: [...builds].sort(), billingIds: [...billingIds].sort() } : {}),
        options: {
            publicKey: {
                challenge: batchId,
                rpId: typeof publicKey.rpId === 'string' ? publicKey.rpId : undefined,
                allowCredentials: Array.isArray(publicKey.allowCredentials)
                    ? (publicKey.allowCredentials as Array<{ type: string; id: string }>)
                    : undefined,
            },
        },
    };
}

export type VaultBatchKeyKind = 'storage' | 'registry' | 'host' | 'session' | 'data' | 'policy' | 'other';

export interface VaultBatchSubject {
    kind: VaultBatchKeyKind;
    /** The app the signed handle names, as 32 lowercase hex characters. */
    appId?: string;
    /** The machine a host key belongs to. It is not an app id. */
    enclaveId?: string;
}

/**
 * What a signed handle says about itself. A handle of a shape the wallet does
 * not know names no app, and the card shows that handle in full.
 */
export function describeVaultHandle(handle: string): VaultBatchSubject {
    const policy = /^app:([^:]+):policy$/.exec(handle);
    if (policy) return APP_ID_HEX.test(policy[1]) ? { kind: 'policy', appId: policy[1] } : { kind: 'other' };

    const parts = handle.split('/');
    if (parts[0] !== 'apps.privasys.org' || !APP_ID_HEX.test(parts[1] ?? '')) return { kind: 'other' };
    const id = parts[1];
    const rest = parts.slice(2);
    if (rest[0] === 'manager' && rest[1] === 'data' && rest.length === 3) return { kind: 'host', enclaveId: id };
    if (rest[0] === 'storage-kek' && rest.length === 2) return { kind: 'storage', appId: id };
    if (rest[0] === 'registry-cred' && rest.length === 2) return { kind: 'registry', appId: id };
    if (rest[0] === 'session-encpub' && rest.length === 3) return { kind: 'session', appId: id };
    if (rest[0] === 'data' && rest.length >= 2) return { kind: 'data', appId: id };
    return { kind: 'other' };
}

/** What one subject of a batch is: a host, an app, or a handle of a shape the
 *  wallet does not know (shown in full, alone). */
export interface VaultBatchGroup {
    key: string;
    subject: 'host' | 'app' | 'other';
    /** The app id (hex) or, for a host, the enclave id. Absent for 'other'. */
    id?: string;
    entries: VerifiedVaultBatchEntry[];
    /** For an app: the version its promotes name, when they all name the same one. */
    versionIdHint?: string;
}

/**
 * The batch as the card shows it: one group per app it touches, so the holder
 * sees which apps an approval affects and what changes for each. A host's own
 * key comes first, since everything on it depends on that; then apps in the
 * order the signed list first names them; then any handle the wallet cannot
 * place. Every entry lands in exactly one group, in its signed order.
 */
export function groupVaultBatch(entries: readonly VerifiedVaultBatchEntry[]): VaultBatchGroup[] {
    const groups = new Map<string, VaultBatchGroup>();
    for (const entry of entries) {
        const s = describeVaultHandle(entry.handle);
        const [key, group]: [string, Omit<VaultBatchGroup, 'entries'>] =
            s.kind === 'host' && s.enclaveId
                ? [`host:${s.enclaveId}`, { key: `host:${s.enclaveId}`, subject: 'host', id: s.enclaveId }]
                : s.appId
                  ? [`app:${s.appId}`, { key: `app:${s.appId}`, subject: 'app', id: s.appId }]
                  : [`other:${entry.handle}`, { key: `other:${entry.handle}`, subject: 'other' }];
        const found = groups.get(key);
        if (found) found.entries.push(entry);
        else groups.set(key, { ...group, entries: [entry] });
    }
    for (const g of groups.values()) {
        const hints = new Set(g.entries.map((e) => e.versionIdHint));
        const only = hints.size === 1 ? [...hints][0] : undefined;
        if (g.subject === 'app' && only) g.versionIdHint = only;
    }
    const rank = { host: 0, app: 1, other: 2 } as const;
    return [...groups.values()]
        .map((g, i) => ({ g, i }))
        .sort((a, b) => rank[a.g.subject] - rank[b.g.subject] || a.i - b.i)
        .map(({ g }) => g);
}

/** The dashed form of an app id, as the control plane reports it. */
export function dashedAppId(hex: string): string {
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Whether the whole list has been on screen. A list that fits has been read as
 * soon as it is laid out; nothing counts before the first layout.
 */
export function reachedEndOfList(m: { offsetY: number; viewportHeight: number; contentHeight: number }): boolean {
    if (m.viewportHeight <= 0 || m.contentHeight <= 0) return false;
    return m.offsetY + m.viewportHeight >= m.contentHeight - 8;
}

/** The name a batch's card registers under while it is on screen. */
export const vaultBatchRouteName = (batchId: string) => `/vault-approvals?batch_id=${batchId}`;
