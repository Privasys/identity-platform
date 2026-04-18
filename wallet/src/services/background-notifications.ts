// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Background notification handler.
 *
 * Registers an Expo TaskManager task that handles push notifications
 * when the app is in the background or killed. This must be imported
 * at the top level (before any component renders) so the task is
 * registered before iOS delivers queued notifications.
 *
 * Only `auth-renew` silent pushes are processed here. Interactive
 * `auth-request` pushes are handled by the foreground listener in
 * useExpoPushToken.ts (user taps the notification to open the app).
 */

import * as TaskManager from 'expo-task-manager';
import { handleSilentRenewal } from '@/services/silent-renew';

const BACKGROUND_NOTIFICATION_TASK = 'BACKGROUND_NOTIFICATION_TASK';

TaskManager.defineTask(BACKGROUND_NOTIFICATION_TASK, async ({ data, error }) => {
    if (error) {
        console.warn('[BG-NOTIFY] Task error:', error);
        return;
    }

    const notification = (data as any)?.notification;
    const pushData = notification?.request?.content?.data ?? notification?.data;

    if (pushData?.type === 'auth-renew' && pushData.sessionId && pushData.rpId && pushData.brokerUrl) {
        try {
            await handleSilentRenewal({
                origin: pushData.origin as string,
                sessionId: pushData.sessionId as string,
                rpId: pushData.rpId as string,
                brokerUrl: pushData.brokerUrl as string,
            });
        } catch (err) {
            console.warn('[BG-NOTIFY] Silent renewal failed:', err);
        }
    }
});

export { BACKGROUND_NOTIFICATION_TASK };
