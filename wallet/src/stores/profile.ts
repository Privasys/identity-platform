// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

/** A linked external identity provider used for profile seeding and recovery. */
export interface LinkedProvider {
    /** Provider identifier: 'github' | 'google' | 'microsoft' | 'linkedin' | custom OIDC issuer URL. */
    provider: string;
    /** Display name for the provider (e.g. "GitHub", "Google"). */
    displayName: string;
    /** Subject identifier from the provider's ID token. */
    sub: string;
    /** Email from the provider (if available). */
    email?: string;
    /** Epoch seconds when linked. */
    linkedAt: number;
    /** Refresh token (encrypted at rest via expo-secure-store). */
    refreshToken?: string;
}

/** Personal data attribute that can be selectively disclosed to enclaves. */
export interface ProfileAttribute {
    /** Attribute key (e.g. 'email', 'displayName', 'phone'). */
    key: string;
    /** Human-readable label. */
    label: string;
    /** The value. */
    value: string;
    /** Whether this was seeded from a linked provider or manually entered. */
    source: 'provider' | 'manual';
    /** Provider ID if source is 'provider'. */
    sourceProvider?: string;
    /** Whether the user has verified this attribute (e.g. email verified by provider). */
    verified: boolean;
}

/** User profile stored locally on the device. */
export interface UserProfile {
    /** Display name. */
    displayName: string;
    /** Email address. */
    email: string;
    /** Avatar URI (local file or remote from linked provider). */
    avatarUri: string;
    /** Locale / language preference. */
    locale: string;
    /** Device-level DID (did:key) derived from this device's hardware key. */
    did: string;
    /** Canonical cross-device DID (did:web:privasys.id:users:<id>). Same across all devices. */
    canonicalDid: string;
    /**
     * Pairwise seed — 32-byte hex string used to derive per-app subject identifiers.
     * Generated once during onboarding, backed up to privasys.id enclave for recovery.
     * MUST be the same across devices for per-app subs to be consistent.
     */
    pairwiseSeed: string;
    /** Linked external identity providers. */
    linkedProviders: LinkedProvider[];
    /** Extended profile attributes for selective disclosure. */
    attributes: ProfileAttribute[];
    /** Epoch seconds of profile creation. */
    createdAt: number;
    /** Epoch seconds of last profile update. */
    updatedAt: number;
}

export interface ProfileState {
    /** The user's profile, or null if not yet created. */
    profile: UserProfile | null;

    /** Create the initial profile (during onboarding or first provider link). */
    createProfile: (profile: Omit<UserProfile, 'createdAt' | 'updatedAt'>) => void;
    /** Update profile fields. */
    updateProfile: (updates: Partial<Pick<UserProfile, 'displayName' | 'email' | 'avatarUri' | 'locale' | 'did' | 'canonicalDid' | 'pairwiseSeed'>>) => void;
    /** Add or update a linked provider. */
    linkProvider: (provider: LinkedProvider) => void;
    /** Remove a linked provider. */
    unlinkProvider: (providerKey: string) => void;
    /** Set a profile attribute (add or overwrite). */
    setAttribute: (attr: ProfileAttribute) => void;
    /** Remove a profile attribute. */
    removeAttribute: (key: string) => void;
    /** Get attributes by keys (for consent/disclosure). */
    getAttributes: (keys: string[]) => ProfileAttribute[];
    /** Clear the entire profile (danger zone). */
    clearProfile: () => void;
    /** Hydrate from secure storage. */
    hydrate: () => Promise<void>;
}

const STORE_KEY = 'v1-profile';

export const useProfileStore = create<ProfileState>((set, get) => ({
    profile: null,

    createProfile: (data) => {
        const now = Math.floor(Date.now() / 1000);
        const profile: UserProfile = { ...data, createdAt: now, updatedAt: now };
        set({ profile });
        persist(profile);
    },

    updateProfile: (updates) => {
        const current = get().profile;
        if (!current) return;
        const updated = {
            ...current,
            ...updates,
            updatedAt: Math.floor(Date.now() / 1000)
        };
        set({ profile: updated });
        persist(updated);
    },

    linkProvider: (provider) => {
        const current = get().profile;
        if (!current) return;
        const existing = current.linkedProviders.findIndex((p) => p.provider === provider.provider);
        const providers =
            existing >= 0
                ? current.linkedProviders.map((p, i) => (i === existing ? provider : p))
                : [...current.linkedProviders, provider];
        const updated = {
            ...current,
            linkedProviders: providers,
            updatedAt: Math.floor(Date.now() / 1000)
        };
        set({ profile: updated });
        persist(updated);
    },

    unlinkProvider: (providerKey) => {
        const current = get().profile;
        if (!current) return;
        const updated = {
            ...current,
            linkedProviders: current.linkedProviders.filter((p) => p.provider !== providerKey),
            updatedAt: Math.floor(Date.now() / 1000)
        };
        set({ profile: updated });
        persist(updated);
    },

    setAttribute: (attr) => {
        const current = get().profile;
        if (!current) return;
        const existing = current.attributes.findIndex((a) => a.key === attr.key);
        const attributes =
            existing >= 0
                ? current.attributes.map((a, i) => (i === existing ? attr : a))
                : [...current.attributes, attr];
        const updated = {
            ...current,
            attributes,
            updatedAt: Math.floor(Date.now() / 1000)
        };
        set({ profile: updated });
        persist(updated);
    },

    removeAttribute: (key) => {
        const current = get().profile;
        if (!current) return;
        const updated = {
            ...current,
            attributes: current.attributes.filter((a) => a.key !== key),
            updatedAt: Math.floor(Date.now() / 1000)
        };
        set({ profile: updated });
        persist(updated);
    },

    getAttributes: (keys) => {
        const current = get().profile;
        if (!current) return [];
        return current.attributes.filter((a) => keys.includes(a.key));
    },

    clearProfile: () => {
        set({ profile: null });
        SecureStore.deleteItemAsync(STORE_KEY).catch(console.error);
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            set({ profile: data });
        } catch {
            // Corrupted data — start fresh
        }
    }
}));

function persist(profile: UserProfile) {
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify(profile)).catch(console.error);
}
