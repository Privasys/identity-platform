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

/** Verification evidence for a verifiable attribute (email, phone, passport, etc.). */
export interface VerificationRecord {
    /** Who performed the verification (e.g. 'google', 'privasys.id', 'nfc-passport'). */
    verifier: string;
    /** Human-readable verifier name for UI display. */
    verifierDisplayName: string;
    /** Verification method (e.g. 'oidc_claim', 'email_code', 'nfc_pace', 'kyc_enclave'). */
    method: 'oidc_claim' | 'email_code' | 'sms_code' | 'nfc_bac' | 'nfc_pace' | 'kyc_enclave' | 'manual';
    /**
     * Assurance level reached by this verification:
     *   'provider' — asserted by a linked IdP (an OIDC claim like email_verified)
     *   'gov'      — certified by the identity-verifier enclave (passport/ID + biometric)
     * Absent/'none' = self-asserted. See kyc-enclave-design.md §3.
     */
    assurance?: 'none' | 'provider' | 'gov';
    /** Epoch seconds when the verification was performed. */
    verifiedAt: number;
    /**
     * Raw evidence from the verifier — e.g. the `email_verified` claim value,
     * NFC certificate chain hash, or verification code receipt ID.
     * Stored for audit trail, never shown to other apps.
     */
    evidence?: string;
}

/**
 * One party that has asserted a given attribute value. Several sources asserting
 * the *same* value strengthen confidence in it (e.g. entered manually, then later
 * confirmed by LinkedIn). See mergeAttribute.
 */
export interface AttributeSource {
    /** How this assertion was obtained. */
    source: 'provider' | 'manual' | 'document' | 'device';
    /** Provider ID if source is 'provider' (e.g. 'google', 'linkedin'). */
    sourceProvider?: string;
    /** Human-readable name for UI display (e.g. "Manual", "LinkedIn", "Passport"). */
    displayName: string;
    /** Epoch seconds when this source asserted the value. */
    addedAt: number;
}

/** Personal data attribute that can be selectively disclosed to enclaves. */
export interface ProfileAttribute {
    /** Canonical attribute key (OIDC Standard Claims: 'email', 'name', etc.). */
    key: string;
    /** Human-readable label. */
    label: string;
    /** The value. */
    value: string;

    // ── Provenance ──────────────────────────────────────────────────────
    /** How this attribute was sourced (the primary / highest-assurance source). */
    source: 'provider' | 'manual' | 'document' | 'device';
    /** Provider ID if source is 'provider' (e.g. 'google', 'microsoft'). */
    sourceProvider?: string;
    /**
     * Every source that has asserted *this value*. Each additional source is a
     * confirmation that strengthens the attribute. Includes the primary source.
     */
    sources?: AttributeSource[];
    /** Epoch seconds when this attribute was first acquired. */
    acquiredAt?: number;
    /** Epoch seconds when this attribute's value was last updated. */
    updatedAt?: number;

    // ── Verification ────────────────────────────────────────────────────
    /** Whether this attribute has been verified by a trusted party. */
    verified: boolean;
    /**
     * Full verification history. Most recent first.
     * Verifiable attributes (email, phone_number) should always have at least
     * one record when `verified` is true.
     */
    verifications?: VerificationRecord[];
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

/** Outcome of mergeAttribute. */
export type MergeResult =
    | { status: 'added' }
    | { status: 'added-value' }
    | { status: 'strengthened'; value: string }
    | { status: 'conflict'; existing: ProfileAttribute; incoming: ProfileAttribute };

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
    /** Set a profile attribute (add or overwrite the first entry with this key). */
    setAttribute: (attr: ProfileAttribute) => void;
    /**
     * Merge an incoming attribute against what is already stored, returning what
     * happened so the UI can resolve conflicts:
     *   - same value already present  → its sources/verifications are merged in
     *     (a confirmation that strengthens the value) and 'strengthened' returned;
     *   - key not present             → the value is added and 'added' returned;
     *   - a different value present and the attribute is multi-valued → the new
     *     value is added alongside and 'added-value' returned;
     *   - a different value present and the attribute is single-valued → nothing
     *     is written and 'conflict' is returned with both values for the caller
     *     to resolve (then call resolveConflict).
     */
    mergeAttribute: (incoming: ProfileAttribute, multiValued: boolean) => MergeResult;
    /**
     * Resolve a single-valued conflict surfaced by mergeAttribute.
     *   'keep'    — keep the existing value (the incoming value is discarded)
     *   'replace' — overwrite with the incoming value and its provenance
     *   'both'    — keep both values (treat the key as multi-valued for this case)
     */
    resolveConflict: (existing: ProfileAttribute, incoming: ProfileAttribute, choice: 'keep' | 'replace' | 'both') => void;
    /** Update the entry matching (key, oldValue) — used by precise inline edits. */
    updateAttributeValue: (key: string, oldValue: string, patch: Partial<ProfileAttribute>) => void;
    /** Remove the single entry matching (key, value). */
    removeAttributeValue: (key: string, value: string) => void;
    /** Remove a profile attribute (all entries with this key). */
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

    mergeAttribute: (incoming, multiValued) => {
        const current = get().profile;
        if (!current) return { status: 'added' };
        const entries = current.attributes.filter((a) => a.key === incoming.key);

        // Brand-new key.
        if (entries.length === 0) {
            const attr = withSources(incoming);
            commitAttributes(set, get, [...current.attributes, attr]);
            return { status: 'added' };
        }

        // Same value already present → strengthen it with the new source.
        const same = entries.find((a) => sameValue(incoming.key, a.value, incoming.value));
        if (same) {
            const merged = strengthen(same, incoming);
            commitAttributes(
                set,
                get,
                current.attributes.map((a) => (a === same ? merged : a)),
            );
            return { status: 'strengthened', value: merged.value };
        }

        // Different value. Multi-valued attributes keep both; single-valued ones
        // surface a conflict for the caller to resolve.
        if (multiValued) {
            commitAttributes(set, get, [...current.attributes, withSources(incoming)]);
            return { status: 'added-value' };
        }
        return { status: 'conflict', existing: entries[0], incoming };
    },

    resolveConflict: (existing, incoming, choice) => {
        const current = get().profile;
        if (!current) return;
        if (choice === 'keep') return;
        if (choice === 'both') {
            commitAttributes(set, get, [...current.attributes, withSources(incoming)]);
            return;
        }
        // 'replace' — swap the existing entry's value/provenance for the incoming one.
        commitAttributes(
            set,
            get,
            current.attributes.map((a) => (a === existing ? withSources(incoming) : a)),
        );
    },

    updateAttributeValue: (key, oldValue, patch) => {
        const current = get().profile;
        if (!current) return;
        commitAttributes(
            set,
            get,
            current.attributes.map((a) =>
                a.key === key && a.value === oldValue
                    ? { ...a, ...patch, updatedAt: Math.floor(Date.now() / 1000) }
                    : a,
            ),
        );
    },

    removeAttributeValue: (key, value) => {
        const current = get().profile;
        if (!current) return;
        commitAttributes(
            set,
            get,
            current.attributes.filter((a) => !(a.key === key && a.value === value)),
        );
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

// ── Attribute-merge helpers ─────────────────────────────────────────────

type SetFn = (partial: { profile: UserProfile }) => void;
type GetFn = () => ProfileState;

/** Persist a new attributes array, bumping the profile's updatedAt. */
function commitAttributes(set: SetFn, get: GetFn, attributes: ProfileAttribute[]) {
    const current = get().profile;
    if (!current) return;
    const updated = { ...current, attributes, updatedAt: Math.floor(Date.now() / 1000) };
    set({ profile: updated });
    persist(updated);
}

/** Whether two values for a key are the same. Email is compared case- and
 *  whitespace-insensitively; everything else exactly (so e.g. "bob"/"Bob" name
 *  variants are treated as a conflict to resolve, per design). */
function sameValue(key: string, a: string, b: string): boolean {
    if (key === 'email') return a.trim().toLowerCase() === b.trim().toLowerCase();
    return a === b;
}

/** Derive the AttributeSource that describes how an attribute was obtained. */
function sourceOf(attr: ProfileAttribute): AttributeSource {
    const displayName =
        attr.source === 'provider'
            ? providerName(attr.sourceProvider)
            : attr.source === 'manual'
            ? 'Manual'
            : attr.source === 'document'
            ? 'ID document'
            : 'Device';
    return {
        source: attr.source,
        sourceProvider: attr.sourceProvider,
        displayName,
        addedAt: attr.acquiredAt ?? Math.floor(Date.now() / 1000),
    };
}

/** Ensure an attribute carries a `sources` list seeded from its primary source. */
function withSources(attr: ProfileAttribute): ProfileAttribute {
    if (attr.sources && attr.sources.length > 0) return attr;
    return { ...attr, sources: [sourceOf(attr)] };
}

const SOURCE_RANK = { device: 0, manual: 1, provider: 2, document: 3 } as const;

/**
 * Fold an incoming assertion of the *same value* into an existing entry: union
 * the source list (a new confirmation), append any new verification records, and
 * promote the primary source to the highest-assurance one. This is what makes
 * "entered manually, then confirmed by LinkedIn" strengthen the attribute.
 */
function strengthen(existing: ProfileAttribute, incoming: ProfileAttribute): ProfileAttribute {
    const sources = [...(existing.sources ?? [sourceOf(existing)])];
    const inSource = sourceOf(incoming);
    const dup = sources.find(
        (s) => s.source === inSource.source && s.sourceProvider === inSource.sourceProvider,
    );
    if (!dup) sources.push(inSource);

    const verifications = [...(existing.verifications ?? [])];
    for (const v of incoming.verifications ?? []) {
        if (!verifications.some((x) => x.verifier === v.verifier && x.method === v.method)) {
            verifications.push(v);
        }
    }

    // Primary source = highest-ranked source backing this value.
    const primary = sources.reduce((best, s) =>
        SOURCE_RANK[s.source] > SOURCE_RANK[best.source] ? s : best,
    );

    return {
        ...existing,
        source: primary.source,
        sourceProvider: primary.sourceProvider,
        sources,
        verifications,
        verified: existing.verified || incoming.verified,
        updatedAt: Math.floor(Date.now() / 1000),
    };
}

function providerName(provider?: string): string {
    if (!provider) return 'Provider';
    const names: Record<string, string> = {
        google: 'Google',
        microsoft: 'Microsoft',
        github: 'GitHub',
        linkedin: 'LinkedIn',
    };
    return names[provider] ?? provider;
}
