// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's approval for a Drive to open their key with a new build.
 *
 * A Drive whose image or host rolled can no longer open the holder's key: the
 * key's rules name the builds that may, and the new one is not among them.
 * Adding it is a change to the key's rules, which only its owner approves.
 *
 * Drive never holds a credential that could ask for that approval. It answers
 * the re-arm with what needs approving, and the WALLET asks privasys.id, as the
 * holder, shows the card, and hands Drive nothing but the approval that comes
 * back: a token good for that one change to that one key.
 *
 * What Drive describes is checked before it is asked for. A Drive speaks only
 * for the holder's key at that Drive: a request naming any other key, another
 * kind of operation, or another platform is refused here and never becomes a
 * card. What is sent to privasys.id is rebuilt from the fields an approval of
 * this kind has: nothing else Drive wrote travels, and how long the approval
 * lives is privasys.id's to set. What the card then shows is read back from
 * privasys.id and checked by the approvals screen, as for every vault approval.
 */

import { callWithPlatformToken } from './platform-token';
import { audienceFor } from './platforms';
import { fetchVaultApproval } from './vault-approval-api';
import { useVaultApprovalsStore } from '../stores/vaultApprovals';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** The longest an approval is waited for: the longest one lives. */
const MAX_WAIT_SECONDS = 300;
const POLL_MS = 2000;

/** The only changes a Drive may ask the holder to approve: to the rules of
 *  the holder's own key there. Never a deletion, an export or a new key. */
const OPERATIONS = new Set(['update_policy', 'update_policy_from']);

/** The older kind of rules change, on a key whose rules ask for it. Its card
 *  cannot show the change: it lets the Drive change the key's rules once,
 *  whatever the change. Until the card says exactly that, the wallet does not
 *  ask for one from here. */
const UNNAMED_CHANGE = 'policy-update';

/** What Drive answers when the owner's approval is needed. Only the fields
 *  requestBody keeps are ever sent on. */
export interface DriveKeyApproval {
    operation: string;
    handle: string;
    audience?: string;
    [field: string]: unknown;
}

/** The fields of an approval that are passed on, with the type each must have. */
const FIELDS: Record<string, 'string' | 'number' | 'strings'> = {
    operation: 'string',
    handle: 'string',
    audience: 'string',
    binding_version: 'number',
    target: 'string',
    policy_version: 'number',
    members: 'strings',
    member_identities: 'strings',
    issuer_index: 'number',
    new_policy: 'string',
    current_policy: 'string',
    measurement_digest: 'string',
};

/** What the card may be told about the request, as short text. */
const CONTEXT = ['app_name', 'app_id', 'key_type', 'summary'];
const CONTEXT_MAX = 200;

/**
 * What is sent to privasys.id: the fields above, each of its own type, and a
 * short context. Anything else Drive wrote is left behind, how long the
 * approval lives among it. A field of the wrong type is a request the wallet
 * does not understand, and nothing is sent.
 */
export function requestBody(approval: DriveKeyApproval): Record<string, unknown> {
    const body: Record<string, unknown> = {};
    for (const [name, type] of Object.entries(FIELDS)) {
        const v = approval[name];
        if (v === undefined || v === null) continue;
        const ok =
            type === 'strings'
                ? Array.isArray(v) && v.every((x) => typeof x === 'string')
                : type === 'number'
                  ? typeof v === 'number' && Number.isInteger(v) && v >= 0
                  : typeof v === 'string';
        if (!ok) throw new Error(`the approval Drive described is not well formed (${name})`);
        body[name] = v;
    }
    // A v1 rules change names no build: the vault is asked for none.
    if (body.operation === 'policy-update') body.measurement_digest = '';
    const given = approval.context;
    if (given && typeof given === 'object' && !Array.isArray(given)) {
        const context: Record<string, string> = {};
        for (const name of CONTEXT) {
            const v = (given as Record<string, unknown>)[name];
            if (typeof v === 'string' && v) context[name] = v.slice(0, CONTEXT_MAX);
        }
        if (Object.keys(context).length) body.context = context;
    }
    return body;
}

/** The approval Drive asks for, from a refused re-arm, or null when the
 *  refusal is anything else. */
export function approvalNeeded(status: number, body: string): DriveKeyApproval | null {
    if (status !== 409) return null;
    let parsed: { error?: unknown; approval?: unknown };
    try {
        parsed = JSON.parse(body);
    } catch {
        return null;
    }
    if (typeof parsed?.error !== 'string' || !parsed.error.startsWith('owner_approval_required')) return null;
    const a = parsed.approval as DriveKeyApproval | undefined;
    if (!a || typeof a !== 'object' || typeof a.operation !== 'string' || typeof a.handle !== 'string') return null;
    return a;
}

/**
 * Whether a refusal from Drive means the holder's key waits on the service's
 * operator: Drive does not take approvals yet, the key must first be moved onto
 * one with bound approvals, or its rules are not on record. There is nothing
 * for the holder to approve, and no card is shown.
 */
export function waitsForOperator(message: string): boolean {
    return /^\s*(approval_not_accepted_yet|move_needed|restage_needed)\s*:/.test(message);
}

const hex = (id: string) => id.toLowerCase().replace(/-/g, '');

/**
 * Why this approval must not be asked for, or null when it may.
 *
 * `appId` is the Drive's id as the wallet verified it from the Drive's
 * attestation, and `audience` the platform that Drive's host belongs to.
 */
export function refusalFor(approval: DriveKeyApproval, appId: string, audience: string): string | null {
    if (approval.operation === UNNAMED_CHANGE) return 'this key uses the older kind of approval, which this version of the wallet does not ask for';
    if (!OPERATIONS.has(approval.operation)) return `it asks for "${approval.operation}", which a Drive may not ask for`;
    const app = hex(appId);
    if (!/^[0-9a-f]{32}$/.test(app)) return 'the Drive could not be identified';
    // A holder's key at a Drive: <domain>/<the Drive's app id>/data/<tenant>/mek/v<n>.
    const m = /^[a-z0-9.-]+\/([0-9a-f]{32})\/data\/[0-9a-f]+\/mek\/v\d+$/.exec(approval.handle);
    if (!m || m[1] !== app) return 'it names a key that is not your key at this Drive';
    // Always named: an approval that says no platform is not assumed to be this one.
    if (approval.audience !== audience) return 'it is not addressed to this platform';
    return null;
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Ask privasys.id for the approval, as the holder, and wait for it.
 *
 * `target` is the control plane or host the Drive belongs to: the wallet's
 * key for that platform authenticates the request. That key is never one the
 * Drive has seen (the Drive is called with its own). Resolves with the
 * approval token once the holder has approved the card; throws when they
 * decline, when it lapses, or when privasys.id refuses the request.
 */
export async function obtainApproval(
    approval: DriveKeyApproval,
    target: string,
    wait: (ms: number) => Promise<void> = sleep,
): Promise<string> {
    const began = await callWithPlatformToken(
        (token) =>
            fetch(`${IDP_BASE}/fido2/vault-approval/begin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify(requestBody(approval)),
            }),
        { interactive: true, target },
    );
    if (!began) throw new Error('the approval could not be asked for: no key for this platform');
    if (!began.res.ok) {
        throw new Error(`the approval could not be asked for (${began.res.status})`);
    }
    const { vault_op: vaultOp } = (await began.res.json()) as { vault_op?: string };
    if (!vaultOp) throw new Error('the approval could not be asked for: no request was opened');

    // The card: the approvals screen reads it back from privasys.id and checks
    // it like any other. This phone is the one asking, so it needs no push.
    useVaultApprovalsStore.getState().remember(vaultOp);

    // How long to wait is what privasys.id says the request lives, never what
    // Drive said; unknown, it is the longest a request lives.
    let seconds = MAX_WAIT_SECONDS;
    try {
        const opened = await fetchVaultApproval(vaultOp);
        const left = opened ? opened.expires_at - Math.floor(Date.now() / 1000) : 0;
        if (left > 0) seconds = Math.min(MAX_WAIT_SECONDS, left);
    } catch {
        /* the longest wait stands */
    }
    const tries = Math.ceil((seconds * 1000) / POLL_MS);
    for (let i = 0; i < tries; i++) {
        await wait(POLL_MS);
        const polled = await callWithPlatformToken(
            (token) =>
                fetch(`${IDP_BASE}/fido2/vault-approval/token?challenge=${encodeURIComponent(vaultOp)}`, {
                    headers: { Authorization: `Bearer ${token}` },
                }),
            { interactive: false, target },
        );
        // No key to ask with just now: the next round has one or the wait ends.
        if (!polled) continue;
        if (polled.res.status === 202) continue;
        if (polled.res.ok) {
            const { access_token: approvalToken } = (await polled.res.json()) as { access_token?: string };
            if (approvalToken) return approvalToken;
            throw new Error('the approval came back empty');
        }
        throw new Error('the approval was declined or has lapsed');
    }
    throw new Error('the approval was not given in time');
}

/** The platform a Drive's control plane or host belongs to. */
export async function platformOf(target: string): Promise<string> {
    return audienceFor(target);
}
