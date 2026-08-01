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
    scope: 'openid' | 'email' | 'profile' | 'phone' | 'address' | 'identity';
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
    /**
     * For enumerated attributes, the URL of the value set that constrains this
     * attribute (e.g. "/referential/locale.json", relative to the IdP). Fetched
     * on demand so the wallet doesn't bundle its own copy. See value-sets.ts.
     */
    valuesUrl?: string;
    /**
     * Whether the client OS can supply this attribute directly (e.g. locale from
     * the device language). Device-sourced attributes are auto-filled and never
     * prompted for. The wallet maps the key to its reader in device-attributes.ts.
     */
    deviceSourced?: boolean;
    /**
     * Whether this attribute can reach 'gov' assurance via the identity-verifier
     * enclave (passport/ID + biometric). Such attributes live under the
     * request-gated 'identity' scope. See the identity-verifier (KYC) design
     */
    identityVerifiable?: boolean;
    /**
     * Whether the wallet may hold more than one value for this key (e.g. several
     * emails or phone numbers). On import, a differing value is added alongside
     * rather than raising a conflict. See profile.mergeAttribute.
     */
    multiValued?: boolean;
    /**
     * This key's own assurance in the registry's vocabulary. Absent means
     * `gov_verified` for an identity-scope key and `self_asserted` otherwise;
     * read it through `attributeAssurance`, never directly.
     */
    assurance?: string;
    /**
     * The government-backed twin of a self-asserted key (`given_name` ->
     * `given_name_id`). The two are separate attributes with separate prices,
     * which is exactly what lets a relying party ask for a first name without
     * demanding a passport.
     */
    govKey?: string;
    /**
     * The spelling that replaces a genuinely retired key: a hint to pickers and
     * new integrators, never a redirect, since the old key keeps working
     * verbatim. No key carries it — the two that did became pairs instead.
     */
    supersededBy?: string;
    /** Never pulled in by a scope: the relying party must name it. Resolved by
     *  the IdP; the wallet only displays the consequence. */
    requestOnly?: boolean;
    /** The identity-verifier field `prove_field` opens for this key, when it
     *  differs from the key. */
    certifiedField?: string;
    /** 'token' (the default for a gov key: an enclave-signed SD-JWT VC from
     *  commit-and-prove) or 'raw' where the enclave deliberately will not
     *  re-certify the value. */
    disclosure?: 'token' | 'raw';
    /** No stored value: the enclave computes it from the identity receipt at
     *  disclosure time, so its absence from the profile is not a gap to fill. */
    derived?: boolean;
    /**
     * Set only for attributes the marketplace issues as a paid disclosure.
     * Absent means free. The wallet does not spend the grant itself (the relying
     * party's voucher does), but it is what lets a consent screen say which of
     * the requested attributes the RP is paying for.
     */
    marketplace?: AttributeMarketplace;
}

/** Registry assurance vocabulary (the `assurance` column of the marketplace's
 *  `attributes` table), not the none/provider/gov ladder — these values are
 *  compared against what the control plane returns. */
export const SELF_ASSERTED = 'self_asserted';
export const GOV_VERIFIED = 'gov_verified';

/**
 * The registry-facing half of an attribute. `key` is the `<namespace>:<name>`
 * spelling the voucher and the billing grant use; a bare name is refused at
 * reservation time, so the two are not interchangeable. It is not
 * `privasys:` + the canonical key either: the registry names the field the
 * ENCLAVE meters, so `given_name_id` is sold as `privasys:given_name`.
 * Price is deliberately absent — the control plane owns it and may reprice.
 */
export interface AttributeMarketplace {
    key: string;
    billable: boolean;
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
    valuesUrl: (a as { valuesUrl?: string }).valuesUrl,
    deviceSourced: (a as { deviceSourced?: boolean }).deviceSourced,
    identityVerifiable: (a as { identityVerifiable?: boolean }).identityVerifiable,
    multiValued: (a as { multiValued?: boolean }).multiValued,
    assurance: (a as { assurance?: string }).assurance,
    govKey: (a as { govKey?: string }).govKey,
    supersededBy: (a as { supersededBy?: string }).supersededBy,
    requestOnly: (a as { requestOnly?: boolean }).requestOnly,
    certifiedField: (a as { certifiedField?: string }).certifiedField,
    disclosure: (a as { disclosure?: 'token' | 'raw' }).disclosure,
    derived: (a as { derived?: boolean }).derived,
    marketplace: (a as { marketplace?: AttributeMarketplace }).marketplace,
}));

/** Lookup table keyed by canonical attribute key. */
export const ATTRIBUTE_MAP: Record<string, AttributeDefinition> =
    Object.fromEntries(CANONICAL_ATTRIBUTES.map((a) => [a.key, a]));

/** All valid canonical attribute keys (for validation). */
export const CANONICAL_KEYS = new Set(CANONICAL_ATTRIBUTES.map((a) => a.key));

/** Ceremonial (non-profile) attribute labels. Requested by relying parties
 *  (e.g. acr=gov-presence adds holder_present) but never stored in the
 *  profile, so deliberately NOT in the canonical referential — adding them
 *  there would make every identity-scope request pull them. */
const CEREMONIAL_LABELS: Record<string, string> = {
    holder_present: 'Physical presence check'
};

/** Human-friendly label for a canonical attribute key. */
export function attributeLabel(key: string): string {
    return ATTRIBUTE_MAP[key]?.label ?? CEREMONIAL_LABELS[key] ?? key;
}

// ── Assurance ───────────────────────────────────────────────────────────
//
// Assurance is a property of the KEY. `given_name` is what the holder typed and
// `given_name_id` is what their passport says: two attributes, two prices, and
// nothing left for a request to disambiguate. The IdP still tells the wallet
// what it needs per attribute in `attributeRequirements[key].assurance`
// ('gov' | 'any'); the wallet honours that answer and never re-decides it, since
// re-deciding from the device is how a relying party's requirement would get
// silently downgraded.

/** This key's assurance in the registry's vocabulary. The scope fallback is for
 *  an older copy of the referential, which carried no field at all: reading an
 *  identity attribute as self-asserted would badge a passport disclosure as
 *  something the holder typed. */
export function attributeAssurance(key: string): string {
    const def = ATTRIBUTE_MAP[key];
    if (!def) return SELF_ASSERTED;
    if (def.assurance) return def.assurance;
    return def.scope === 'identity' ? GOV_VERIFIED : SELF_ASSERTED;
}

/** Whether disclosing this key means disclosing something a government document
 *  evidenced. */
export function isGovVerified(key: string): boolean {
    return attributeAssurance(key) === GOV_VERIFIED;
}

/**
 * The identity-verifier field `prove_field` opens for a key.
 *
 * It differs from the key exactly where a gov key carries the `_id` suffix the
 * enclave never saw: the passport commitment is `given_name`, and asking for
 * `given_name_id` is rejected as an uncertified field. That rejection is what
 * used to make a gov-verified first name 400 and be silently dropped.
 */
export function certifiedFieldFor(key: string): string {
    return ATTRIBUTE_MAP[key]?.certifiedField ?? key;
}

/**
 * Whether a gov key is answered by an enclave-signed disclosure at all.
 *
 * The DG2 portrait is the exception the referential marks `disclosure: 'raw'`:
 * the identity-verifier commits to it so a fresh selfie can be matched against
 * it, and until the marketplace prices the disclosure there is no voucher to
 * authorise a fresh certification. A relying party that asks for the ID photo
 * gets the wallet's stored copy — gov PROVENANCE, no fresh enclave signature —
 * and is never billed, because there is no metered enclave work. Without this
 * the wallet would call prove_field and drop the attribute on the rejection,
 * which is exactly what it did.
 */
export function disclosesAsToken(key: string): boolean {
    return ATTRIBUTE_MAP[key]?.disclosure !== 'raw';
}

/** Whether the enclave computes this key from the identity receipt rather than
 *  the wallet storing it. A derived key is never a gap in the profile, and the
 *  holder must never be prompted for one. */
export function isDerived(key: string): boolean {
    return ATTRIBUTE_MAP[key]?.derived === true;
}

/**
 * Whether disclosing this key reveals the underlying document value.
 *
 * Two very different things are both "gov-verified", and telling the holder
 * they are the same is a lie in one direction:
 *
 *   - `age_over_18` answers a QUESTION about the date of birth. The date stays
 *     in the wallet; the relying party learns only yes or no.
 *   - `birthdate_id` IS the date of birth, certified. Consenting shares the
 *     value itself — signed, but fully readable by the relying party.
 *
 * The referential marks the second kind with `certifiedField`: the document
 * field the credential opens. Anything without one is an insight computed from
 * the identity receipt, and the source data never leaves.
 */
export function revealsUnderlyingValue(key: string): boolean {
    const def = ATTRIBUTE_MAP[key];
    if (!def) return false;
    return !!def.certifiedField && def.derived !== true;
}

/**
 * The marketplace attribute key a requested attribute discloses as, in the
 * provider-namespaced form the relying party's voucher authorises.
 *
 * Read off the referential, never rebuilt as `privasys:${key}`: the namespace
 * belongs to whichever provider sells the attribute, and an `_id` key is sold
 * under the field the enclave meters (`given_name_id` -> `privasys:given_name`).
 * Only the ceremonial keys deliberately absent from the referential
 * (holder_present) fall back to the platform's own namespace.
 */
export function marketplaceKeyFor(key: string): string {
    return ATTRIBUTE_MAP[key]?.marketplace?.key ?? `privasys:${key}`;
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
 * Highest assurance recorded for a canonical attribute, or undefined if the
 * attribute is not present. Enforces the assurance model: a 'gov' requirement
 * is satisfied only by an enclave-verified (document) value, never a
 * self-asserted ('manual') or provider one. Top-level profile fields
 * (email/name/locale/picture) are never gov-assured.
 */
export function getProfileAssurance(
    profile: UserProfile,
    key: string,
): 'none' | 'provider' | 'gov' | undefined {
    const attrs = (profile.attributes ?? []).filter((a) => a.key === key);
    if (attrs.length === 0) return getProfileValue(profile, key) ? 'none' : undefined;
    const rank = { none: 0, provider: 1, gov: 2 } as const;
    let best: 'none' | 'provider' | 'gov' = 'none';
    for (const attr of attrs) {
        if (attr.source === 'document' && rank.gov > rank[best]) best = 'gov';
        for (const v of attr.verifications ?? []) {
            if (v.assurance && rank[v.assurance] > rank[best]) best = v.assurance;
        }
    }
    return best;
}

/**
 * The profile key holding a government-assured value for `key`, or undefined
 * when the holder has none.
 *
 * Usually the key itself. The fallback exists because a document value was
 * imported under the enclave's own field name before the `_id` spelling did:
 * a wallet that verified a passport last year holds `birthdate`, and a request
 * for `birthdate_id` is the same disclosure under the newer name, so refusing it
 * would ask the holder to re-scan a document the wallet has already certified.
 *
 * The assurance check on the fallback is the whole safety of it. `given_name_id`
 * also falls back to `given_name`, which is exactly the self-asserted value a
 * relying party asking for a passport name must never receive — and it is
 * rejected here, because a manually typed name is not document-sourced.
 */
export function govValueKey(profile: UserProfile, key: string): string | undefined {
    if (getProfileValue(profile, key) && getProfileAssurance(profile, key) === 'gov') return key;
    const alt = ATTRIBUTE_MAP[key]?.certifiedField;
    if (alt && alt !== key && getProfileValue(profile, alt) && getProfileAssurance(profile, alt) === 'gov') {
        return alt;
    }
    return undefined;
}

/**
 * Move document-sourced values off the SELF-ASSERTED half of a dual-tier pair.
 *
 * Profiles verified before the split hold the passport reading under the bare
 * key: a wallet that scanned a passport last year has a gov-assured
 * `birthdate`, and one that scanned it after has `birthdate_id`. A wallet that
 * did both shows the holder the same date twice, each "certified by Privasys
 * identity verifier", which is how this was found.
 *
 * Leaving it was judged harmless because govValueKey answers a `birthdate_id`
 * request from a gov-assured `birthdate`. It is not harmless. The referential
 * publishes `birthdate` as SELF-ASSERTED, so a relying party asking for the
 * free key — believing it is getting a value the holder typed — receives a
 * passport reading instead, discloses it for nothing, and the marketplace never
 * sees the paid disclosure it should have been. The split exists precisely so
 * those two are different attributes; a legacy profile quietly merges them
 * again.
 *
 * So the value moves to the government key, and the bare key is left for what
 * it now means: something the holder typed. Nothing is deleted that cannot be
 * re-derived — the government key keeps the value, its provenance and its
 * verification records. A bare key that is NOT document-sourced is untouched:
 * a manually entered date is exactly what the self-asserted half is for.
 */
export function migrateDualTierAssurance(profile: UserProfile): {
    moved: string[];
    dropped: string[];
    attributes: ProfileAttribute[];
} {
    const attrs = profile.attributes ?? [];
    const moved: string[] = [];
    const dropped: string[] = [];
    const out: ProfileAttribute[] = [];

    for (const attr of attrs) {
        const govKey = ATTRIBUTE_MAP[attr.key]?.govKey;
        const isDocument = attr.source === 'document';
        if (!govKey || !isDocument) {
            out.push(attr);
            continue;
        }
        // The government key already holds this reading — the bare copy is a
        // duplicate of it, and duplicates are what the holder is looking at.
        const already = attrs.some((a) => a.key === govKey && a.value === attr.value);
        if (already) {
            dropped.push(attr.key);
            continue;
        }
        out.push({ ...attr, key: govKey, label: attributeLabel(govKey) });
        moved.push(attr.key);
    }
    return { moved, dropped, attributes: out };
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
                assurance: 'provider',
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
        sources: Array<{ source: string; displayName: string; addedAt: string }>;
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
            sources: (a.sources ?? []).map((s) => ({
                source: s.source,
                displayName: s.displayName,
                addedAt: new Date(s.addedAt * 1000).toISOString(),
            })),
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
