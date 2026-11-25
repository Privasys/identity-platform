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
 * card. What the card then shows is read back from privasys.id and checked by
 * the approvals screen, as for every vault approval.
 */

import { callWithPlatformToken } from './platform-token';
import { audienceFor } from './platforms';
import { useVaultApprovalsStore } from '../stores/vaultApprovals';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** The longest an approval is waited for: the longest one lives. */
const MAX_WAIT_SECONDS = 300;
const POLL_MS = 2000;

/** The only changes a Drive may ask the holder to approve: to the rules of
 *  the holder's own key there. Never a deletion, an export or a new key. */
const OPERATIONS = new Set(['policy-update', 'update_policy', 'update_policy_from']);

/** What Drive answers when the owner's approval is needed, passed on to
 *  privasys.id as it stands. */
export interface DriveKeyApproval {
    operation: string;
    handle: string;
    audience?: string;
    ttl_seconds?: number;
    [field: string]: unknown;
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

const hex = (id: string) => id.toLowerCase().replace(/-/g, '');

/**
 * Why this approval must not be asked for, or null when it may.
 *
 * `appId` is the Drive's id as the wallet verified it from the Drive's
 * attestation, and `audience` the platform that Drive's host belongs to.
 */
export function refusalFor(approval: DriveKeyApproval, appId: string, audience: string): string | null {
    if (!OPERATIONS.has(approval.operation)) return `it asks for "${approval.operation}", which a Drive may not ask for`;
    const app = hex(appId);
    if (!/^[0-9a-f]{32}$/.test(app)) return 'the Drive could not be identified';
    // A holder's key at a Drive: <domain>/<the Drive's app id>/data/<tenant>/mek/v<n>.
    const m = /^[a-z0-9.-]+\/([0-9a-f]{32})\/data\/[0-9a-f]+\/mek\/v\d+$/.exec(approval.handle);
    if (!m || m[1] !== app) return 'it names a key that is not your key at this Drive';
    if (approval.audience !== undefined && approval.audience !== audience) return 'it is addressed to another platform';
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
                body: JSON.stringify(approval),
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

    const seconds = Math.min(MAX_WAIT_SECONDS, typeof approval.ttl_seconds === 'number' && approval.ttl_seconds > 0 ? approval.ttl_seconds : MAX_WAIT_SECONDS);
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
