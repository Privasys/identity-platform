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
    /** Whether the user has confirmed saving their CURRENT recovery phrase.
     *  False on a fresh wallet, whenever a phrase is (re)generated (until the
     *  user confirms), and whenever a flow invalidates the phrase (account
     *  recovery, deactivation). Drives the persistent "save your recovery
     *  phrase" nudge — the server only knows has_phrase, not whether the human
     *  ever wrote it down. */
    recoveryPhraseSaved: boolean;

    // Actions
    setOnboarded: () => void;
    addCredential: (credential: Credential) => void;
    removeCredential: (credentialId: string) => void;
    getCredentialForRp: (rpId: string) => Credential | undefined;
    getCredentialById: (credentialId: string) => Credential | undefined;
    setUnlocked: (durationMs: number) => void;
    checkUnlocked: () => boolean;
    setPrivasysId: (account: PrivasysIdAccount | null) => void;
    setPrivasysSession: (sessionToken: string, ttlMs: number) => void;
    setRecoveryPhraseSaved: (saved: boolean) => void;
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
    recoveryPhraseSaved: false,

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
        // One rpId can carry credentials for MULTIPLE accounts (the shared
        // privasys.id RP after an account recovery registers a second
        // account's credential). Array order means oldest-wins — exactly
        // wrong after a recovery, where the newest registration is the
        // account the user just deliberately bound to this device
        // (2026-07-30: a stale entry shadowed the freshly recovered admin
        // credential and every sign-in landed on the wrong account). Prefer
        // the newest; the full answer for multi-account RPs is an account
        // chooser in the ceremony.
        return [...get().credentials]
            .filter((c) => c.rpId === rpId)
            .sort((a, b) => (b.registeredAt ?? 0) - (a.registeredAt ?? 0))[0];
    },

    getCredentialById: (credentialId) => {
        return get().credentials.find((c) => c.credentialId === credentialId);
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

    setRecoveryPhraseSaved: (saved) => {
        set({ recoveryPhraseSaved: saved });
        persist(get());
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            let credentials: Credential[] = data.credentials ?? [];
            let privasysId: PrivasysIdAccount | null = data.privasysId ?? null;
            // Normalise: the meta-account's credential lives in the privasysId
            // slot, never in credentials[]. Slot-unaware flows (pre-2026-07-30
            // recovery) left meta credentials in the list, where they shadow
            // the platform credential and show up as a confusing duplicate
            // privasys.id row. Match on the slot's own recorded userId (not a
            // derived value — profile seeds differ across installs): a list
            // entry for the same account supersedes the slot's stale pointer,
            // so adopt it and drop the list copy. Hardware keys are untouched.
            if (privasysId?.userId) {
                const stray = credentials.find(
                    (c) => c.userHandle === privasysId!.userId && c.credentialId !== privasysId!.credentialId,
                );
                if (stray) {
                    privasysId = {
                        ...privasysId,
                        credentialId: stray.credentialId,
                        keyAlias: stray.keyAlias,
                        sessionToken: '',
                        sessionExpiresAt: 0,
                    };
                    credentials = credentials.filter((c) => c.credentialId !== stray.credentialId);
                }
            }
            set({
                isOnboarded: data.isOnboarded ?? false,
                credentials,
                privasysId,
                recoveryPhraseSaved: data.recoveryPhraseSaved ?? false,
            });
            persist(get());
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
        recoveryPhraseSaved: state.recoveryPhraseSaved,
    };
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify(data)).catch(console.error);
}
