// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';

/**
 * Thin wrapper around expo-secure-store that falls back to localStorage on web.
 * Native modules are lazy-imported to avoid crashing the web bundle.
 */

let _secureStore: typeof import('expo-secure-store') | null = null;

async function getSecureStore() {
    if (Platform.OS === 'web') return null;
    if (!_secureStore) {
        _secureStore = await import('expo-secure-store');
    }
    return _secureStore;
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
    if (store) return store.setItemAsync(key, value, options);
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
