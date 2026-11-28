// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The system's notification module, loaded once, with the wallet's rule for
 * which notifications show a banner while the wallet is open.
 */

import { Platform } from 'react-native';

import { APPROVAL_TYPE } from './approval';

/**
 * Requests the holder is waiting on right now, because they started something
 * elsewhere: a sign-in, an app reaching another enclave, an approval. Received
 * while the wallet is open, these open at once and show no banner. Anything
 * else (an app's message or form, a Drive share, a deletion notice) shows its
 * banner and opens only on a tap, as it does when the wallet is closed, so it
 * never takes the holder away from what they are doing.
 */
const OPENS_AT_ONCE = new Set<string>([
    'auth-request',
    'voucher-request',
    'vault-approval',
    'vault-approval-batch',
    'attribute-approval',
    'capability-request',
    'recovery-request',
    APPROVAL_TYPE,
]);

export function opensAtOnce(data: Record<string, unknown> | undefined): boolean {
    return typeof data?.type === 'string' && OPENS_AT_ONCE.has(data.type);
}

let handlerSet = false;

/** expo-notifications, with the banner rule set the first time it is asked for. */
export async function getNotifications() {
    // Loaded when first needed, as the hook did, so nothing native loads
    // before the first screen asks.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const Notifications = require('expo-notifications') as typeof import('expo-notifications');
    if (!handlerSet && Platform.OS !== 'web') {
        handlerSet = true;
        Notifications.setNotificationHandler({
            handleNotification: async (notification) => {
                // A request that opens at once needs no banner too: the
                // holder is already looking at its screen.
                const data = notification?.request?.content?.data as Record<string, unknown> | undefined;
                const quiet = opensAtOnce(data);
                return {
                    shouldShowAlert: !quiet,
                    shouldPlaySound: !quiet,
                    shouldSetBadge: !quiet,
                    shouldShowBanner: !quiet,
                    shouldShowList: !quiet,
                };
            },
        });
    }
    return Notifications;
}
