// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A notification answered on one phone leaves the holder's other phones too.
 *
 * Each phone gets its own copy of a push, and iOS clears only the copy that was
 * tapped. So the phone that answers tells privasys.id (POST /push/dismiss), which
 * sends the holder's other phones a silent push carrying the same key; each
 * removes the delivered notification with that key, from the background task
 * (background-tasks.ts) or, when open, from the push listener.
 *
 * The key is a hash of the notification's type and request id: the id itself
 * (a sign-in session, a vault capability) does not travel again.
 *
 * Apple rations silent pushes, so a phone may not hear in time. The tray sweep
 * the wallet runs when it opens takes away what can no longer be answered.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { Platform } from 'react-native';

import { bytesToBase64url } from '../utils/encoding';

/** The silent push's type. */
export const DISMISS_TYPE = 'notification-dismiss';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** The field naming the request, by notification type. */
const REQUEST_ID: Record<string, string> = {
    'auth-request': 'sessionId',
    'voucher-request': 'sessionId',
    'vault-approval': 'vault_op',
    'vault-approval-batch': 'batch_id',
    'attribute-approval': 'approval',
    'capability-request': 'nonce',
    approval: 'message_id',
    'app-form': 'message_id',
    'app-message': 'message_id',
};

/** Types whose request expires within minutes: their notification is no use
 *  after STALE_AFTER_MS. The longest of them is a capability ask, 15 minutes. */
const SHORT_LIVED = new Set([
    'auth-request',
    'voucher-request',
    'vault-approval',
    'vault-approval-batch',
    'attribute-approval',
    'capability-request',
]);
export const STALE_AFTER_MS = 15 * 60 * 1000;

type Data = Record<string, unknown> | undefined | null;

/** The notifications module, loaded when first needed: never on the web, and
 *  not while the wallet is only starting up. */
function notifications(): typeof import('expo-notifications') {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('expo-notifications');
}

/** The key both phones derive for one notification, or null for one that
 *  names no request (it is then left to the phone it is on). */
export function notificationKey(data: Data): string | null {
    const type = typeof data?.type === 'string' ? data.type : '';
    const field = REQUEST_ID[type];
    const id = field ? data?.[field] : undefined;
    if (typeof id !== 'string' || !id) return null;
    return bytesToBase64url(sha256(new TextEncoder().encode(`privasys-notification\x00${type}\x00${id}`))).slice(0, 22);
}

/** Whether a notification delivered at `date` asks for something that has expired. */
export function isStale(data: Data, date: number, now = Date.now()): boolean {
    const type = typeof data?.type === 'string' ? data.type : '';
    return SHORT_LIVED.has(type) && date > 0 && now - date > STALE_AFTER_MS;
}

/** Expo hands a notification's date in seconds on some paths, milliseconds on others. */
function millis(date: number): number {
    return date > 0 && date < 1e12 ? date * 1000 : date;
}

/** Remove this phone's delivered notifications with `key`. */
export async function dismissHere(key: string): Promise<number> {
    if (Platform.OS === 'web' || !key) return 0;
    const Notifications = notifications();
    const presented = await Notifications.getPresentedNotificationsAsync();
    let n = 0;
    for (const p of presented) {
        if (notificationKey(p.request.content.data as Data) === key) {
            await Notifications.dismissNotificationAsync(p.request.identifier);
            n++;
        }
    }
    return n;
}

/** Remove this phone's delivered notifications that can no longer be answered. */
export async function dismissStale(now = Date.now()): Promise<number> {
    if (Platform.OS === 'web') return 0;
    const Notifications = notifications();
    const presented = await Notifications.getPresentedNotificationsAsync();
    let n = 0;
    for (const p of presented) {
        if (isStale(p.request.content.data as Data, millis(p.date), now)) {
            await Notifications.dismissNotificationAsync(p.request.identifier);
            n++;
        }
    }
    return n;
}

/** Tell the holder's other phones that this notification was answered here.
 *  Best effort: they clear it on expiry anyway. */
export async function dismissElsewhere(data: Data, pushToken: string | null): Promise<void> {
    const key = notificationKey(data);
    if (!key || !pushToken) return;
    // Any other copy on this phone too (the tapped one iOS has already removed).
    await dismissHere(key).catch(() => 0);
    try {
        // Signed by this phone's binding key: a push token alone is not a secret.
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { dismissProof } = require('./push-bind') as typeof import('./push-bind');
        const proof = await dismissProof(pushToken, key);
        const res = await fetch(`${IDP_BASE}/push/dismiss`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ push_token: pushToken, key, ...proof }),
        });
        if (!res.ok) console.warn(`[notifications] dismiss elsewhere: ${res.status}`);
    } catch (e) {
        console.warn('[notifications] dismiss elsewhere failed', e);
    }
}

/** This phone's push token, once the wallet knows it: what names the holder's
 *  other phones to privasys.id. Set by the push hook. */
let ownPushToken: string | null = null;
export function setOwnPushToken(token: string | null): void {
    ownPushToken = token;
}

/**
 * A request was answered in the wallet itself, approved or declined: take its
 * notification off this phone and off the holder's others.
 *
 * Tapping a notification already does this. But a request is often answered
 * without its notification ever being tapped (the wallet was open, or was
 * opened from its icon), and its notification then stayed on every device
 * until it expired.
 */
export function requestAnswered(type: string, id: string): void {
    const field = REQUEST_ID[type];
    if (!field || !id) return;
    void dismissElsewhere({ type, [field]: id }, ownPushToken).catch(() => undefined);
    // With no token yet there is nobody to tell, but this phone's copy still goes.
    if (!ownPushToken) {
        const key = notificationKey({ type, [field]: id });
        if (key) void dismissHere(key).catch(() => 0);
    }
}

/**
 * Remove this phone's delivered notifications for requests that are no longer
 * open, as privasys.id reports them. `open` holds the ids still pending, by
 * notification type; a type it does not list is left alone.
 */
export async function dismissClosed(open: Record<string, Set<string>>): Promise<number> {
    if (Platform.OS === 'web') return 0;
    const Notifications = notifications();
    const presented = await Notifications.getPresentedNotificationsAsync();
    let n = 0;
    for (const p of presented) {
        const data = p.request.content.data as Data;
        const type = typeof data?.type === 'string' ? data.type : '';
        const ids = open[type];
        const field = REQUEST_ID[type];
        const id = field ? data?.[field] : undefined;
        if (!ids || typeof id !== 'string' || !id || ids.has(id)) continue;
        await Notifications.dismissNotificationAsync(p.request.identifier);
        n++;
    }
    return n;
}

/**
 * The number on the app's icon: how many things are waiting on the holder.
 * Set whenever the wallet knows the count, so the icon is right from the
 * moment the wallet has been open; zero clears it.
 */
export async function setAppBadge(count: number): Promise<void> {
    if (Platform.OS === 'web') return;
    try {
        const Notifications = notifications();
        await Notifications.setBadgeCountAsync(Math.max(0, Math.min(99, Math.floor(count))));
    } catch (e) {
        console.warn('[notifications] badge not set', e);
    }
}

/** The data of a push as the background task receives it: Expo's data object,
 *  as a JSON string or under `body`, depending on platform and version. */
export function backgroundPushData(payload: unknown): Data {
    const d = (payload as { data?: Record<string, unknown> } | null)?.data;
    if (!d) return null;
    if (typeof d.dataString === 'string') {
        try {
            return JSON.parse(d.dataString) as Record<string, unknown>;
        } catch {
            return null;
        }
    }
    const body = d.body;
    if (typeof body === 'string') {
        try {
            return JSON.parse(body) as Record<string, unknown>;
        } catch {
            return null;
        }
    }
    if (body && typeof body === 'object') return body as Record<string, unknown>;
    return d;
}
