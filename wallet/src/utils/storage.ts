// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';

/**
 * Thin wrapper around expo-secure-store that falls back to localStorage on web.
 * Native modules are lazy-imported to avoid crashing the web bundle.
 *
 * Everything the wallet writes stays on this phone: on iOS the default is
 * WHEN_UNLOCKED_THIS_DEVICE_ONLY, so neither an encrypted backup nor a
 * phone-to-phone transfer (Quick Start) carries it: they would carry the
 * secrets without the passkeys, which live in the Secure Enclave and never
 * move. A new phone gets the wallet from the old one (services/device-flows)
 * or from the recovery phrase. Android keeps these out of its backups
 * (plugins/android-backup-rules.js).
 */

let _secureStore: typeof import('expo-secure-store') | null = null;

async function getSecureStore() {
    if (Platform.OS === 'web') return null;
    if (!_secureStore) {
        _secureStore = await import('expo-secure-store');
    }
    return _secureStore;
}

function deviceOnly(
    store: typeof import('expo-secure-store'),
    options?: import('expo-secure-store').SecureStoreOptions,
): import('expo-secure-store').SecureStoreOptions | undefined {
    if (options || Platform.OS !== 'ios') return options;
    return { keychainAccessible: store.WHEN_UNLOCKED_THIS_DEVICE_ONLY };
}

export async function getItemAsync(
    key: string,
    options?: import('expo-secure-store').SecureStoreOptions
): Promise<string | null> {
    const store = await getSecureStore();
    if (store) return store.getItemAsync(key, options);
    if (typeof localStorage !== 'undefined') return localStorage.getItem(key);
    return null;
}

export async function setItemAsync(
    key: string,
    value: string,
    options?: import('expo-secure-store').SecureStoreOptions
): Promise<void> {
    const store = await getSecureStore();
    if (store) return store.setItemAsync(key, value, deviceOnly(store, options));
    if (typeof localStorage !== 'undefined') localStorage.setItem(key, value);
}

export async function deleteItemAsync(
    key: string,
    options?: import('expo-secure-store').SecureStoreOptions
): Promise<void> {
    const store = await getSecureStore();
    if (store) return store.deleteItemAsync(key, options);
    if (typeof localStorage !== 'undefined') localStorage.removeItem(key);
}

export type { SecureStoreOptions } from 'expo-secure-store';
