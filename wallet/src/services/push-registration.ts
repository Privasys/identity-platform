// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Telling privasys.id this phone's push token: once at start when the wallet
 * holds a live session, after each sign-in with that identity's session, and
 * again when the holder changes what the phone wants (the number on its icon).
 */

import * as Device from 'expo-device';
import { Platform } from 'react-native';

import { mainAccountUserId, myDeviceTag } from './devices';
import { ensureNotifySealKey } from './notify-seal';
import { getPrivasysAccount } from './privasys-id';
import { registrationProof, repeatWhenBound } from './push-bind';
import { getNotifications } from './push-notifications';
import { getPushToken, setPushToken } from './push-token';
import { useSettingsStore } from '../stores/settings';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/**
 * Register the wallet's Expo push token with the IdP under a given wallet
 * session's identity. Called after each sign-in with that identity's session,
 * so every identity that owns vault keys can be pushed, without the IdP
 * learning any link between identities it does not already have.
 */
export async function registerPushTokenWithIdp(
    walletSessionToken: string,
    expoPushToken: string,
    encPub: string,
    /** The IdP user id the session is for: names this phone's target on it. */
    userId: string,
    /** Set on the repeat made after a challenge, which is not repeated again. */
    repeating = false,
): Promise<void> {
    // The device tag keeps one target per phone; without one the registration
    // stands untagged.
    let deviceTag = '';
    try {
        deviceTag = await myDeviceTag(userId);
    } catch {
        /* registers untagged */
    }
    // The proof that this token is this phone's (services/push-bind). Without
    // it the registration stands, unbound.
    let proof: Awaited<ReturnType<typeof registrationProof>> | Record<string, never> = {};
    try {
        proof = await registrationProof(expoPushToken, userId);
    } catch {
        /* registers unbound */
    }
    // Whether this device wants its icon's number sent with its pushes. Not
    // said before the settings are read: privasys.id then keeps what it last
    // heard.
    const settings = useSettingsStore.getState();
    const badge = settings.hydrated ? { badge: settings.iconBadge } : {};
    const res = await fetch(`${IDP_BASE}/push-token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer wallet:${walletSessionToken}`,
        },
        // enc_pub is the device's X25519 notification-sealing key; the
        // IdP seals app-notification payloads to it (empty keeps any
        // previously registered key).
        // device_tag keeps one target per phone of the holder; every phone is notified.
        body: JSON.stringify({ push_token: expoPushToken, enc_pub: encPub, ...(deviceTag ? { device_tag: deviceTag } : {}), ...proof, ...badge }),
    });
    if (!res.ok) {
        throw new Error(`register push token failed (${res.status})`);
    }
    // Unbound: privasys.id is sending this phone a challenge, or has one out.
    // Once it is answered the registration is made again, signed.
    if (!repeating) {
        const bound = await res
            .json()
            .then((b: { bound?: boolean }) => b?.bound === true)
            .catch(() => false);
        if (!bound) {
            repeatWhenBound(userId, () => registerPushTokenWithIdp(walletSessionToken, expoPushToken, encPub, userId, true));
        }
    }
}

/**
 * Register the token under the wallet's own privasys.id session, with the
 * device's notification-sealing key so app notifications (Drive share
 * requests) can carry sealed payloads. Best effort, and only with a session
 * still valid: a cold start often holds a stored but expired one, which
 * privasys.id refuses. The next sign-in registers with a fresh session.
 */
async function registerWithWalletSession(token: string): Promise<void> {
    const account = getPrivasysAccount();
    if (!account?.sessionToken) return;
    if (!account.sessionExpiresAt || Date.now() >= account.sessionExpiresAt) return;
    try {
        let encPub = '';
        try {
            encPub = await ensureNotifySealKey();
        } catch (e) {
            console.warn('[notifications] sealing key unavailable; registering token alone', e);
        }
        await registerPushTokenWithIdp(account.sessionToken, token, encPub, mainAccountUserId(account.userId));
    } catch (e) {
        console.warn('[notifications] register push token with IdP failed', e);
    }
}

/** Tell privasys.id again what this device wants (the number on its icon),
 *  when the wallet holds a live session. Otherwise the next sign-in does. */
export async function registerPushTokenAgain(): Promise<void> {
    const token = getPushToken();
    if (token) await registerWithWalletSession(token);
}

let started = false;

/**
 * Ask for permission to notify, read this phone's token, and register it.
 * Once per process; nothing on a simulator or the web.
 */
export async function registerForPushNotifications(): Promise<void> {
    if (started) return;
    started = true;
    if (Platform.OS === 'web' || !Device.isDevice) return;
    const Notifications = await getNotifications();

    const { status: existingStatus } = await Notifications.getPermissionsAsync();
    let finalStatus = existingStatus;
    if (existingStatus !== 'granted') {
        const { status } = await Notifications.requestPermissionsAsync();
        finalStatus = status;
    }
    if (finalStatus !== 'granted') return;

    const token = (await Notifications.getExpoPushTokenAsync()).data;
    setPushToken(token);
    // Tell the IdP our token so it can push vault approvals to this owner.
    void registerWithWalletSession(token);

    if (Platform.OS === 'android') {
        Notifications.setNotificationChannelAsync('default', {
            name: 'default',
            importance: Notifications.AndroidImportance.MAX,
        });
    }
}
