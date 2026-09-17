// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Sorting the holder's standing grants into the two things they actually are.
 *
 * A grant over the holder's own Drive and a grant carrying the holder's Gmail
 * password are not the same sort of thing, and the difference is not the kind
 * of data. It is who can end it. We hold the first, so revoking ends it. The
 * second is a credential for an account at a provider we have nothing to do
 * with, so revoking stops the service and leaves the credential alive until the
 * holder removes it there.
 *
 * What separates them is whether the holder typed a secret into the service's
 * setup form when they approved it.
 */

import { capabilityKey, type CapabilityRecord } from '@/stores/capabilities';

export type AccessGroup = 'account' | 'data';

export interface AccessRow {
    /** Stable identity of the underlying record. */
    key: string;
    group: AccessGroup;
    record: CapabilityRecord;
}

/** Which of the two a record belongs to. */
export function groupOf(r: CapabilityRecord): AccessGroup {
    return r.setupProvided ? 'account' : 'data';
}

/**
 * Standing grants, newest first, denials excluded.
 *
 * A denial is in the store so a re-prompt can say the holder declined before.
 * It is not access, so it does not belong on a screen about what has access.
 * Revoked and expired rows DO stay: "you removed this on 17 September" is an
 * answer, and a row that vanishes silently is not.
 */
export function accessRows(records: CapabilityRecord[]): AccessRow[] {
    return records
        .filter((r) => r.decision === 'approved')
        .slice()
        .sort((a, b) => b.grantedAt - a.grantedAt)
        .map((record) => ({ key: capabilityKey(record), group: groupOf(record), record }));
}

/** Rows in one group. */
export function rowsInGroup(records: CapabilityRecord[], group: AccessGroup): AccessRow[] {
    return accessRows(records).filter((r) => r.group === group);
}

/**
 * Whether a row still represents access the holder could withdraw. Revoked,
 * expired and gone rows are history: they stay visible and stop offering a
 * button that would do nothing.
 */
export function isLive(r: CapabilityRecord, nowSeconds: number): boolean {
    if (r.revokedAt || r.checkResult === 'gone') return false;
    return !(r.expiresAt && r.expiresAt <= nowSeconds);
}

/** How many rows in a group are still live, for the section count. */
export function liveCount(records: CapabilityRecord[], group: AccessGroup, nowSeconds: number): number {
    return rowsInGroup(records, group).filter((r) => isLive(r.record, nowSeconds)).length;
}
