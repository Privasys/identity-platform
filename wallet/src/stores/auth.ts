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
    /** The RP ID returned by the enclave during registration (for rpIdHash). */
    serverRpId?: string;
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
    /** The wallet's own privasys.id meta-account (for recovery management). */
    privasysId: PrivasysIdAccount | null;

    // Actions
    setOnboarded: () => void;
    addCredential: (credential: Credential) => void;
    removeCredential: (credentialId: string) => void;
    getCredentialForRp: (rpId: string) => Credential | undefined;
    setUnlocked: (durationMs: number) => void;
    checkUnlocked: () => boolean;
    setPrivasysId: (account: PrivasysIdAccount | null) => void;
    setPrivasysSession: (sessionToken: string, ttlMs: number) => void;
    hydrate: () => Promise<void>;
}

/** The wallet's own account at privasys.id (used for recovery management). */
export interface PrivasysIdAccount {
    /** Stable user id at privasys.id. */
    userId: string;
    /** Last sessionToken issued by FIDO2 register/authenticate. */
    sessionToken: string;
    /** Epoch ms when the sessionToken expires (~30 min). */
    sessionExpiresAt: number;
    /** Credential id used for re-authentication. */
    credentialId: string;
    /** Hardware key alias for re-authentication. */
    keyAlias: string;
}

const STORE_KEY = 'v1-auth-store';

export const useAuthStore = create<AuthState>((set, get) => ({
    isOnboarded: false,
    credentials: [],
    isUnlocked: false,
    unlockExpiresAt: 0,
    privasysId: null,

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

    setPrivasysId: (account) => {
        set({ privasysId: account });
        persist(get());
    },

    setPrivasysSession: (sessionToken, ttlMs) => {
        const cur = get().privasysId;
        if (!cur) return;
        const updated = { ...cur, sessionToken, sessionExpiresAt: Date.now() + ttlMs };
        set({ privasysId: updated });
        persist(get());
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            set({
                isOnboarded: data.isOnboarded ?? false,
                credentials: data.credentials ?? [],
                privasysId: data.privasysId ?? null,
            });
        } catch {
            // Corrupted data — start fresh
        }
    }
}));

function persist(state: AuthState) {
    const data = {
        isOnboarded: state.isOnboarded,
        credentials: state.credentials,
        privasysId: state.privasysId,
    };
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify(data)).catch(console.error);
}
