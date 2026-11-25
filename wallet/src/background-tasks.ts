// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the wallet does on a push while it is closed or in the background.
 *
 * Imported first by the entry (entry.ts): iOS and Android wake the app for a
 * silent push by loading the bundle without drawing anything, and a task must be
 * defined in that first pass to run. Kept small for that reason.
 *
 * Two jobs: a notification answered on another of the holder's phones is
 * removed here (services/notification-dismiss), and a challenge from
 * privasys.id to show this phone's push token is its own is answered
 * (services/push-bind).
 */

import * as Notifications from 'expo-notifications';
import * as TaskManager from 'expo-task-manager';
import { Platform } from 'react-native';

import { backgroundPushData, dismissHere, DISMISS_TYPE } from './services/notification-dismiss';
import { answerBindChallenge, BIND_TYPE } from './services/push-bind';

export const NOTIFICATION_TASK = 'privasys-notification';

if (Platform.OS !== 'web') {
    TaskManager.defineTask(NOTIFICATION_TASK, async ({ data }) => {
        const push = backgroundPushData(data);
        if (push?.type === BIND_TYPE) {
            // With the phone locked its keys cannot be read; the wallet asks
            // for a new challenge the next time it registers.
            try {
                const token = (await Notifications.getExpoPushTokenAsync()).data;
                const bound = await answerBindChallenge(push, token);
                return bound
                    ? Notifications.BackgroundNotificationTaskResult.NewData
                    : Notifications.BackgroundNotificationTaskResult.NoData;
            } catch {
                return Notifications.BackgroundNotificationTaskResult.Failed;
            }
        }
        if (push?.type !== DISMISS_TYPE || typeof push.key !== 'string') {
            return Notifications.BackgroundNotificationTaskResult.NoData;
        }
        try {
            const n = await dismissHere(push.key);
            return n > 0
                ? Notifications.BackgroundNotificationTaskResult.NewData
                : Notifications.BackgroundNotificationTaskResult.NoData;
        } catch {
            return Notifications.BackgroundNotificationTaskResult.Failed;
        }
    });
    Notifications.registerTaskAsync(NOTIFICATION_TASK).catch((e) =>
        console.warn('[notifications] background task not registered', e),
    );
}
