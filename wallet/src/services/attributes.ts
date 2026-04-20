// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Canonical attribute system — defines the standard set of user attributes
 * that the Privasys wallet and IdP understand.
 *
 * Attribute names follow the OIDC Standard Claims specification (RFC 7519 §5.1)
 * so they map naturally to JWT claims and OIDC scopes. External identity
 * providers (Google, Microsoft, GitHub, LinkedIn) return claims under
 * provider-specific keys — the mappings here normalise them into our
 * canonical set.
 *
 * Only attributes in the CANONICAL_ATTRIBUTES list can be requested via
 * the SDK's `requestedAttributes` and stored in the IdP auth codes. The
 * wallet profile store maps its internal fields to these canonical names.
 */

import type { ProfileAttribute, UserProfile, VerificationRecord } from '@/stores/profile';

// ── Canonical attribute definitions ─────────────────────────────────────
// Loaded from the shared JSON file (single source of truth for IdP + wallet).
// The file is copied from auth/shared/ into wallet/src/shared/ for Metro/EAS
// bundler compatibility (EAS builds copy only the wallet directory).

import canonicalDoc from '../shared/canonical-attributes.json';

export interface AttributeDefinition {
    /** Canonical key (matches OIDC Standard Claims where applicable). */
    key: string;
    /** Human-readable label for UI display. */
    label: string;
    /** OIDC scope that gates this attribute. */
    scope: 'openid' | 'email' | 'profile' | 'phone' | 'address';
    /**
     * Corresponding top-level field on UserProfile, if any.
     * Attributes without a profileField are stored in the `attributes` bag.
     */
    profileField?: keyof Pick<UserProfile, 'displayName' | 'email' | 'avatarUri' | 'locale'>;
    /**
     * Whether this attribute can be verified by a trusted party.
     * When true, the wallet enforces that provider-sourced values carry
     * a verification record — unverified values from providers are rejected.
     */
    verifiable: boolean;
}

// Map JSON profileField strings to the typed union.
const PROFILE_FIELD_MAP: Record<string, keyof Pick<UserProfile, 'displayName' | 'email' | 'avatarUri' | 'locale'>> = {
    displayName: 'displayName',
    email: 'email',
    avatarUri: 'avatarUri',
    locale: 'locale',
};

/**
 * The canonical attribute list — loaded from shared/canonical-attributes.json.
 * This is the single source of truth for what attributes the platform supports.
 */
export const CANONICAL_ATTRIBUTES: AttributeDefinition[] = canonicalDoc.attributes.map((a) => ({
    key: a.key,
    label: a.label,
    scope: a.scope as AttributeDefinition['scope'],
    profileField: a.profileField ? PROFILE_FIELD_MAP[a.profileField] : undefined,
    verifiable: a.verifiable,
}));

/** Lookup table keyed by canonical attribute key. */
export const ATTRIBUTE_MAP: Record<string, AttributeDefinition> =
    Object.fromEntries(CANONICAL_ATTRIBUTES.map((a) => [a.key, a]));

/** All valid canonical attribute keys (for validation). */
export const CANONICAL_KEYS = new Set(CANONICAL_ATTRIBUTES.map((a) => a.key));

/** Human-friendly label for a canonical attribute key. */
export function attributeLabel(key: string): string {
    return ATTRIBUTE_MAP[key]?.label ?? key;
}

// ── Profile ↔ canonical mapping ─────────────────────────────────────────

/**
 * Read a canonical attribute value from a UserProfile.
 * Checks the top-level profileField first, then falls back to the
 * `attributes` bag.
 */
export function getProfileValue(profile: UserProfile, key: string): string | undefined {
    const def = ATTRIBUTE_MAP[key];
    if (def?.profileField) {
        const val = profile[def.profileField];
        if (val) return val;
    }
    // Fall back to extended attributes bag
    return profile.attributes?.find((a) => a.key === key)?.value || undefined;
}

/**
 * Write a canonical attribute to the profile store using the appropriate
 * method (top-level field update or attribute bag).
 */
export function setProfileValue(
    store: {
        updateProfile: (u: Partial<Pick<UserProfile, 'displayName' | 'email' | 'avatarUri' | 'locale'>>) => void;
        setAttribute: (attr: ProfileAttribute) => void;
    },
    key: string,
    value: string,
    source: 'provider' | 'manual' | 'document',
    opts: {
        sourceProvider?: string;
        verified?: boolean;
        verifications?: VerificationRecord[];
    } = {},
): void {
    const def = ATTRIBUTE_MAP[key];
    const now = Math.floor(Date.now() / 1000);

    // Update the top-level profile field if this attribute has one.
    if (def?.profileField) {
        store.updateProfile({ [def.profileField]: value } as any);
    }

    // Always store in the attributes bag for consistent lookup.
    store.setAttribute({
        key,
        label: def?.label ?? key,
        value,
        source,
        sourceProvider: opts.sourceProvider,
        acquiredAt: now,
        updatedAt: now,
        verified: opts.verified ?? false,
        verifications: opts.verifications ?? [],
    });
}

// ── Provider claim normalisation ────────────────────────────────────────
// Loaded from the shared JSON (single source of truth for IdP + wallet).

/** Provider claim key → canonical attribute key. */
const PROVIDER_CLAIM_MAP: Record<string, Record<string, string>> = Object.fromEntries(
    Object.entries(canonicalDoc.providers).map(([name, prov]) => [name, prov.claimMap]),
);

/** Canonical attribute key → raw claim key that indicates verification status. */
const PROVIDER_VERIFICATION_CLAIMS: Record<string, Record<string, string>> = Object.fromEntries(
    Object.entries(canonicalDoc.providers)
        .filter(([, prov]) => Object.keys(prov.verificationClaims).length > 0)
        .map(([name, prov]) => [name, prov.verificationClaims]),
);

/**
 * Normalise raw provider claims into canonical attribute key/value pairs.
 * Only returns attributes that are in the canonical list. When multiple
 * provider keys map to the same canonical key, the first non-empty value
 * wins (so order in the raw object matters less — we iterate the mapping
 * table, not the raw data).
 */
export function normalizeProviderClaims(
    provider: string,
    raw: Record<string, unknown>,
): Record<string, string> {
    const mapping = PROVIDER_CLAIM_MAP[provider];
    if (!mapping) {
        // Unknown provider — try direct passthrough for canonical keys only.
        const result: Record<string, string> = {};
        for (const [k, v] of Object.entries(raw)) {
            if (CANONICAL_KEYS.has(k) && typeof v === 'string' && v) {
                result[k] = v;
            }
        }
        return result;
    }

    const result: Record<string, string> = {};
    for (const [providerKey, canonicalKey] of Object.entries(mapping)) {
        // Skip if we already have a value for this canonical key or if not in our list.
        if (result[canonicalKey]) continue;
        if (canonicalKey !== 'sub' && !CANONICAL_KEYS.has(canonicalKey)) continue;

        const val = raw[providerKey];
        if (val != null && val !== '') {
            result[canonicalKey] = String(val);
        }
    }
    return result;
}

/**
 * Check whether a provider claims an attribute is verified.
 * Returns true if the provider's verification claim is truthy, or if the
 * provider is known to only return verified values for that attribute.
 */
export function isProviderVerified(
    provider: string,
    canonicalKey: string,
    raw: Record<string, unknown>,
): boolean {
    const verificationClaims = PROVIDER_VERIFICATION_CLAIMS[provider];
    if (!verificationClaims) return false;

    const claimKey = verificationClaims[canonicalKey];
    if (!claimKey) return false;

    // Special sentinel: provider only returns verified values for this attribute.
    if (claimKey === '_always_verified') return true;

    const val = raw[claimKey];
    return val === true || val === 'true';
}

/**
 * Build ProfileAttribute entries from normalised claims with full provenance
 * and verification records. Filters out 'sub' (never stored as an attribute).
 *
 * For verifiable attributes (email, phone_number), the attribute is only
 * accepted as verified if the provider explicitly confirms it. Unverified
 * verifiable attributes are still stored but marked `verified: false`.
 */
export function claimsToProfileAttributes(
    normalised: Record<string, string>,
    provider: string,
    raw: Record<string, unknown>,
): ProfileAttribute[] {
    const now = Math.floor(Date.now() / 1000);
    const attrs: ProfileAttribute[] = [];

    for (const [key, value] of Object.entries(normalised)) {
        if (key === 'sub' || !value) continue;
        const def = ATTRIBUTE_MAP[key];
        if (!def) continue;

        const providerVerified = isProviderVerified(provider, key, raw);
        const verified = def.verifiable ? providerVerified : false;

        const verifications: VerificationRecord[] = [];
        if (verified) {
            verifications.push({
                verifier: provider,
                verifierDisplayName: providerDisplayName(provider),
                method: 'oidc_claim',
                verifiedAt: now,
                evidence: `${provider}:${key}_verified=true`,
            });
        }

        attrs.push({
            key,
            label: def.label,
            value,
            source: 'provider',
            sourceProvider: provider,
            acquiredAt: now,
            updatedAt: now,
            verified,
            verifications,
        });
    }
    return attrs;
}

/** Human-friendly name for a provider key. */
function providerDisplayName(provider: string): string {
    const names: Record<string, string> = {
        google: 'Google',
        microsoft: 'Microsoft',
        github: 'GitHub',
        linkedin: 'LinkedIn',
    };
    return names[provider] ?? provider;
}

/**
 * Export all profile attributes as a JSON-serialisable audit object.
 * Includes full provenance and verification records.
 */
export function exportAttributesForAudit(profile: UserProfile): {
    exportedAt: string;
    did: string;
    canonicalDid: string;
    attributes: Array<{
        key: string;
        label: string;
        value: string;
        source: string;
        sourceProvider?: string;
        acquiredAt: string;
        updatedAt: string;
        verified: boolean;
        verifications: Array<{
            verifier: string;
            verifierDisplayName: string;
            method: string;
            verifiedAt: string;
            evidence?: string;
        }>;
    }>;
    linkedProviders: Array<{
        provider: string;
        displayName: string;
        sub: string;
        email?: string;
        linkedAt: string;
    }>;
} {
    return {
        exportedAt: new Date().toISOString(),
        did: profile.did,
        canonicalDid: profile.canonicalDid,
        attributes: (profile.attributes ?? []).map((a) => ({
            key: a.key,
            label: a.label,
            value: a.value,
            source: a.source,
            sourceProvider: a.sourceProvider,
            acquiredAt: new Date((a.acquiredAt ?? 0) * 1000).toISOString(),
            updatedAt: new Date((a.updatedAt ?? 0) * 1000).toISOString(),
            verified: a.verified,
            verifications: (a.verifications ?? []).map((v) => ({
                verifier: v.verifier,
                verifierDisplayName: v.verifierDisplayName,
                method: v.method,
                verifiedAt: new Date(v.verifiedAt * 1000).toISOString(),
                evidence: v.evidence,
            })),
        })),
        linkedProviders: profile.linkedProviders.map((p) => ({
            provider: p.provider,
            displayName: p.displayName,
            sub: p.sub,
            email: p.email,
            linkedAt: new Date(p.linkedAt * 1000).toISOString(),
        })),
    };
}
