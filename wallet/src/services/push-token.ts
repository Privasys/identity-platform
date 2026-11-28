// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * This phone's Expo push token: what names the phone to privasys.id, kept in
 * one place for everything that needs it (registering it, answering a binding
 * challenge, clearing a notification on the holder's other phones).
 *
 * The push hook asks for permission and sets the token once it has it. A
 * notification can be handled before that (a wallet opened by a tap handles
 * the tap first), so ensurePushToken reads the token from the system then:
 * a notification arrived, so the phone has one.
 */

let current: string | null = null;
const subscribers = new Set<(token: string | null) => void>();

/** The token, once known. */
export function getPushToken(): string | null {
    return current;
}

/** Set the token, and tell whoever is waiting on it. */
export function setPushToken(token: string | null): void {
    current = token;
    for (const fn of subscribers) fn(token);
}

/** Be told each time the token is set. Returns the unsubscribe. */
export function subscribePushToken(fn: (token: string | null) => void): () => void {
    subscribers.add(fn);
    return () => {
        subscribers.delete(fn);
    };
}

/** The token, read from the system when it is not known yet. Null on the web or when it cannot be read. */
export async function ensurePushToken(): Promise<string | null> {
    if (current) return current;
    try {
        // Loaded when first needed, so the modules that only read the token
        // (push-bind among them) stay free of the native runtime.
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { Platform } = require('react-native') as typeof import('react-native');
        if (Platform.OS === 'web') return null;
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const Notifications = require('expo-notifications') as typeof import('expo-notifications');
        const token = (await Notifications.getExpoPushTokenAsync()).data;
        if (!current && token) setPushToken(token);
    } catch {
        /* no token to be had */
    }
    return current;
}
