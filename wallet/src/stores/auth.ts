// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

/** A registered FIDO2 credential. */
export interface Credential {
    /** Base64url credential ID (from WebAuthn). */
    credentialId: string;
    /** Relying party ID. */
    rpId: string;
    /** The app origin this credential is registered with. */
    origin: string;
    /** Hardware key alias used for this credential. */
    keyAlias: string;
    /** User handle (opaque RP-assigned identifier). */
    userHandle: string;
    /** Display name for the user. */
    userName: string;
    /** Epoch seconds of registration. */
    registeredAt: number;
}

export interface AuthState {
    /** Whether the wallet has completed initial setup. */
    isOnboarded: boolean;
    /** All registered FIDO2 credentials. */
    credentials: Credential[];
    /** Whether biometric grace period is active (skip re-prompt). */
    isUnlocked: boolean;
    /** Epoch ms when the current unlock expires. */
    unlockExpiresAt: number;

    // Actions
    setOnboarded: () => void;
    addCredential: (credential: Credential) => void;
    removeCredential: (credentialId: string) => void;
    getCredentialForRp: (rpId: string) => Credential | undefined;
    setUnlocked: (durationMs: number) => void;
    checkUnlocked: () => boolean;
    hydrate: () => Promise<void>;
}

const STORE_KEY = 'v1-auth-store';

export const useAuthStore = create<AuthState>((set, get) => ({
    isOnboarded: false,
    credentials: [],
    isUnlocked: false,
    unlockExpiresAt: 0,

    setOnboarded: () => {
        set({ isOnboarded: true });
        persist(get());
    },

    addCredential: (credential) => {
        set((s) => ({ credentials: [...s.credentials, credential] }));
        persist(get());
    },

    removeCredential: (credentialId) => {
        set((s) => ({
            credentials: s.credentials.filter((c) => c.credentialId !== credentialId)
        }));
        persist(get());
    },

    getCredentialForRp: (rpId) => {
        return get().credentials.find((c) => c.rpId === rpId);
    },

    setUnlocked: (durationMs) => {
        const expiresAt = Date.now() + durationMs;
        set({ isUnlocked: true, unlockExpiresAt: expiresAt });
    },

    checkUnlocked: () => {
        const s = get();
        if (!s.isUnlocked) return false;
        if (Date.now() > s.unlockExpiresAt) {
            set({ isUnlocked: false, unlockExpiresAt: 0 });
            return false;
        }
        return true;
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            set({
                isOnboarded: data.isOnboarded ?? false,
                credentials: data.credentials ?? []
            });
        } catch {
            // Corrupted data — start fresh
        }
    }
}));

function persist(state: AuthState) {
    const data = {
        isOnboarded: state.isOnboarded,
        credentials: state.credentials
    };
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify(data)).catch(console.error);
}
