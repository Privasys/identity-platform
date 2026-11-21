// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the wallet does when it hears about an account deletion: the pushes
 * privasys.id sends, and the checks at start-up for anything it missed while
 * closed (a push the holder never tapped runs no code).
 *
 * Kept apart from services/account-deletion because clearing the wallet
 * (services/wipe) needs that module, and this one needs the wipe.
 */

import {
    cancelIdentityMarks,
    checkGone,
    flushDeletionOutbox,
    refreshDeletionState,
} from '@/services/account-deletion';
import { wipeWallet } from '@/services/wipe';
import { i18next } from '@/i18n';
import { notify } from '@/stores/notice';

/** The pushes privasys.id sends about a deletion. Each carries only its type. */
export const DELETION_PUSH_TYPES = new Set([
    'account-deletion-scheduled',
    'account-deletion-reminder',
    'account-deletion-cancelled',
    'account-deleted',
    // This device was removed from the holder's wallet by another one.
    'device-removed',
]);

/** Handle one of DELETION_PUSH_TYPES. Never clears the wallet on the push alone. */
export async function handleDeletionPush(type: string): Promise<void> {
    switch (type) {
        case 'account-deletion-scheduled':
        case 'account-deletion-reminder':
            await refreshDeletionState('pending');
            return;
        case 'account-deletion-cancelled':
            // Cancelled from another device, or by a phrase recovery: this
            // wallet unmarks the identities it holds (it may be all of them).
            await cancelIdentityMarks();
            return;
        case 'account-deleted':
        case 'device-removed':
            // Only privasys.id's own answer (the tombstone) clears anything.
            await clearIfGone();
            return;
    }
}

let clearing = false;

/**
 * Clear this wallet if, and only if, privasys.id answers that its account was
 * deleted or this device removed. Returns whether it did.
 */
export async function clearIfGone(): Promise<boolean> {
    if (clearing) return false;
    const reason = await checkGone();
    if (!reason) return false;
    clearing = true;
    try {
        await wipeWallet();
        const t = i18next.t.bind(i18next);
        if (reason === 'account_deleted') notify(t('accountDeletion.goneTitle'), t('accountDeletion.goneBody'));
        else notify(t('accountDeletion.removedTitle'), t('accountDeletion.removedBody'));
        return true;
    } finally {
        clearing = false;
    }
}

/**
 * At start-up, once the stores are loaded: send any marks still waiting,
 * refresh the banner, and clear the wallet if its account or this device is
 * gone. Best effort and silent: offline, it tries again next time.
 */
export async function deletionStartup(): Promise<void> {
    try {
        if (await clearIfGone()) return;
        await flushDeletionOutbox();
        await refreshDeletionState();
    } catch (e: any) {
        console.warn('[account-deletion] start-up check failed:', e?.message ?? e);
    }
}
