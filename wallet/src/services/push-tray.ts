// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';

import { fileDriveNotification, isDriveShare } from './drive-share-push';
import { isClosed, isStale } from './notification-dismiss';
import { answerBindChallenge, carriesBindChallenge } from './push-bind';
import { getNotifications } from './push-notifications';
import { useGuardianRequestsStore } from '../stores/guardian-requests';
import { useVaultApprovalsStore } from '../stores/vaultApprovals';

/**
 * One pass over the notifications in the tray, when the wallet comes up or to
 * the front. A notification the holder never tapped (the wallet was opened
 * from its icon) has no response event and no cold-start record, so this is
 * how what it carries reaches the wallet. For each, in order:
 *
 *  - a binding challenge it carries is answered, before anything is cleared;
 *  - a request that can no longer be answered is cleared;
 *  - an approval, a guardian's recovery request or a Drive share is filed.
 *
 * Then, when approvals were filed, privasys.id is asked which are still open
 * and the others are cleared: answered on another of the holder's phones, or
 * expired. The silent push that would clear them is rationed by Apple and
 * never reaches a wallet that was swiped away.
 */
export async function sweepTray(): Promise<void> {
    if (Platform.OS === 'web') return;
    try {
        const Notifications = await getNotifications();
        const presented = await Notifications.getPresentedNotificationsAsync();
        const store = useVaultApprovalsStore.getState();
        const dismiss = (identifier: string) => Notifications.dismissNotificationAsync(identifier).catch(() => undefined);
        const kept: typeof presented = [];
        let approvals = false;
        let bound = false;
        for (const n of presented) {
            const data = n.request.content.data as Record<string, unknown> | undefined;
            if (!bound && carriesBindChallenge(data)) {
                bound = await answerBindChallenge(data).catch((e) => {
                    console.warn('[notifications] push binding from the tray failed', e);
                    return false;
                });
            }
            if (isStale(data, n.date)) {
                await dismiss(n.request.identifier);
                continue;
            }
            kept.push(n);
            if (data?.type === 'vault-approval' && data.vault_op) {
                store.remember(String(data.vault_op));
                approvals = true;
            }
            if (data?.type === 'vault-approval-batch' && data.batch_id) {
                store.rememberBatch(String(data.batch_id));
                approvals = true;
            }
            // A guardian's recovery request: Access shows it as waiting even
            // when the wallet was opened from its icon rather than the push.
            if (data?.type === 'recovery-request') {
                useGuardianRequestsStore.getState().remember();
            }
            // Drive share notifications carry their sealed payload in the
            // notification itself: filing from the tray means the request
            // (and its attributes) are visible as soon as the wallet opens,
            // tap or no tap.
            if (data && isDriveShare(data)) {
                void fileDriveNotification(data).catch((e) => console.warn('[notifications] could not file drive notification', e));
            }
        }
        if (approvals) {
            await store.refresh();
            await store.refreshBatches();
            const live = useVaultApprovalsStore.getState();
            // Known less the ones privasys.id reports gone: a request it could
            // not be asked about just now stays, so a lost connection never
            // takes a live notification away.
            const open = {
                'vault-approval': new Set(live.knownOps),
                'vault-approval-batch': new Set(live.batchIds),
            };
            for (const n of kept) {
                if (isClosed(n.request.content.data as Record<string, unknown> | undefined, open)) await dismiss(n.request.identifier);
            }
        }
    } catch (e) {
        console.warn('[notifications] tray pass failed', e);
    }
}
