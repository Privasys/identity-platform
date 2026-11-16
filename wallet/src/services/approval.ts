// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Approvals: an app asking the holder to approve one act (a decision with
 * legal or lasting effect), now, at an assurance it names.
 *
 * Unlike a form, the shape is fixed and the wallet owns the whole screen: a
 * title, labelled lines, and two answers, Approve and Decline. The app also
 * sends the digest of the act it will commit, which the wallet never
 * computes: it is bound into the passkey challenge and the token, and the app
 * recomputes it from the act before committing.
 *
 * Assurance:
 *   - device: the phone's own biometric, prompted afresh for this approval;
 *   - gov-presence: a live selfie matched to the holder's verified passport
 *     photo, then the passkey (not yet built; the IdP refuses it at notify).
 *
 * This file only parses. Confirming the sender and answering live in
 * services/approval-answer, which needs native modules.
 */

import { cleanText, formDigest, isPath, onlyKeys } from '@/services/app-form';

export const APPROVAL_TYPE = 'approval';

export type Assurance = 'device' | 'gov-presence';
export type Decision = 'approve' | 'decline';

export interface Approval {
    id: string;
    title: string;
    lines: { label: string; value: string }[];
    actDigest: string;
    assurance: Assurance;
    callback: string;
    ttl: number;
    /** Hex SHA-256 of the exact approval string. */
    digest: string;
}

const MAX_APPROVAL_BYTES = 3 << 10;

/** Parse and check an approval string, or null: what the wallet would not
 *  draw is never shown, whatever the IdP accepted. */
export function parseApproval(approval: unknown): Approval | null {
    if (typeof approval !== 'string' || approval === '' || new TextEncoder().encode(approval).length > MAX_APPROVAL_BYTES) {
        return null;
    }
    let raw: Record<string, unknown>;
    try {
        raw = JSON.parse(approval);
    } catch {
        return null;
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    if (!onlyKeys(raw, ['v', 'id', 'title', 'lines', 'act_digest', 'assurance', 'callback', 'ttl'])) return null;
    if (raw.v !== 1 || typeof raw.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(raw.id)) return null;
    const title = cleanText(raw.title, 120, false);
    if (!title) return null;
    const rawLines = raw.lines ?? [];
    if (!Array.isArray(rawLines) || rawLines.length > 12) return null;
    const lines: { label: string; value: string }[] = [];
    for (const l of rawLines as Record<string, unknown>[]) {
        if (!l || typeof l !== 'object' || !onlyKeys(l, ['label', 'value'])) return null;
        const label = cleanText(l.label, 40, false);
        const value = cleanText(l.value, 200, false);
        if (!label || !value) return null;
        lines.push({ label, value });
    }
    if (typeof raw.act_digest !== 'string' || !/^[0-9a-f]{64}$/.test(raw.act_digest)) return null;
    if (raw.assurance !== 'device' && raw.assurance !== 'gov-presence') return null;
    if (!isPath(raw.callback)) return null;
    if (typeof raw.ttl !== 'number' || !Number.isInteger(raw.ttl) || raw.ttl < 60 || raw.ttl > 900) return null;
    return {
        id: raw.id,
        title,
        lines,
        actDigest: raw.act_digest,
        assurance: raw.assurance,
        callback: raw.callback,
        ttl: raw.ttl,
        digest: formDigest(approval),
    };
}

/** The approval inside a payload {approval: "<string>"}, or null. */
export function readApprovalPayload(payload: Record<string, unknown> | null | undefined): Approval | null {
    return payload ? parseApproval(payload.approval) : null;
}
