// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The canonical attribute referential, as the SDK's integration surface.
 *
 * Every front end that wanted to know what a relying party can ask for used to
 * fetch https://privasys.id/referential/canonical-attributes.json and fold it
 * into a local shape of its own: the developer portal's registration form, the
 * Drive share picker, and anything an integrator wrote. Three folders of the
 * same document, three interpretations of what "gov" means, and three places for
 * a new attribute to be forgotten. The list ships here instead, and the IdP keeps
 * serving the raw document for consumers that are not on this SDK.
 *
 * The bundled copy is generated from auth/shared/canonical-attributes.json by
 * `npm run sync-shared`, and CI re-runs that and fails on a diff — the same
 * guard the wallet's copy has, for the same reason: a copy nobody regenerates
 * goes stale silently, and the IdP's once did so by eleven attributes.
 */

import canonicalDoc from './shared/canonical-attributes.json';

/** Registry assurance vocabulary (the `assurance` column of the marketplace's
 *  `attributes` table), not the none/provider/gov ladder used inside tokens. */
export const SELF_ASSERTED = 'self_asserted';
export const GOV_VERIFIED = 'gov_verified';

/**
 * The registry-facing half of an attribute. `key` is the `<namespace>:<name>`
 * spelling a voucher and a billing grant must agree on; a bare name is refused
 * at reservation time. It is not `privasys:` + the canonical key either: the
 * registry names the field the enclave meters, so `given_name_id` is sold as
 * `privasys:given_name`. Price is deliberately absent, since the control plane
 * owns it and may reprice at any time.
 */
export interface AttributeMarketplace {
    key: string;
    billable: boolean;
}

/** One canonical attribute. */
export interface CanonicalAttribute {
    /** Canonical key, following OIDC Standard Claims where one applies. */
    key: string;
    /** Human-readable label, for a picker or a consent screen. */
    label: string;
    /** The OIDC scope that reaches this key, for a client still requesting by
     *  scope. A request-only key is reachable only by name. */
    scope: string;
    /** Whether a trusted party can verify the value (an OIDC claim such as
     *  email_verified), short of a government document. */
    verifiable?: boolean;
    /** Whether the identity-verifier enclave can evidence this attribute,
     *  either because the key IS the government-backed one or because it has
     *  one (see `govKey`). */
    identityVerifiable?: boolean;
    /** Whether the holder may hold more than one value (several emails). */
    multiValued?: boolean;
    /** The value set that constrains this attribute, relative to the issuer. */
    valuesUrl?: string;
    /** This key's own assurance. Read it through `assuranceOf`, which supplies
     *  the fallback an older copy of the document relies on. */
    assurance?: string;
    /** The government-backed twin of a self-asserted key. */
    govKey?: string;
    /** The `_id` spelling that replaces a key minted before the convention. */
    supersededBy?: string;
    /** Never reached by a scope: the relying party must name it. */
    requestOnly?: boolean;
    /** The identity-verifier field the disclosure opens, when it differs. */
    certifiedField?: string;
    /** 'raw' for a government-sourced value the enclave will not re-certify. */
    disclosure?: string;
    /** No stored value: computed in the enclave from the identity receipt. */
    derived?: boolean;
    /** Present only when the marketplace sells this attribute. */
    marketplace?: AttributeMarketplace;
}

/** The canonical list, in referential order. */
export const CANONICAL_ATTRIBUTES: CanonicalAttribute[] =
    (canonicalDoc as { attributes: CanonicalAttribute[] }).attributes;

/** Lookup by canonical key. */
export const ATTRIBUTE_MAP: Record<string, CanonicalAttribute> = Object.fromEntries(
    CANONICAL_ATTRIBUTES.map((a) => [a.key, a]),
);

/** Every canonical key, for validating what an integrator asks for before the
 *  IdP silently drops it. */
export const CANONICAL_KEYS: ReadonlySet<string> = new Set(CANONICAL_ATTRIBUTES.map((a) => a.key));

/**
 * This key's assurance in the registry's vocabulary.
 *
 * The scope fallback matters for `fetchAttributeReferential`, which may load a
 * document older than this bundle: reading an identity attribute as
 * self-asserted would badge a passport disclosure as something the holder typed.
 */
export function assuranceOf(attr: CanonicalAttribute | string | undefined): string {
    const a = typeof attr === 'string' ? ATTRIBUTE_MAP[attr] : attr;
    if (!a) return SELF_ASSERTED;
    if (a.assurance) return a.assurance;
    return a.scope === 'identity' ? GOV_VERIFIED : SELF_ASSERTED;
}

/** Whether disclosing this key means disclosing something a government document
 *  evidenced. This is the distinction to show a user, not the `_id` suffix. */
export function isGovVerified(attr: CanonicalAttribute | string | undefined): boolean {
    return assuranceOf(attr) === GOV_VERIFIED;
}

/** Whether requesting this attribute costs the relying party credits. The PRICE
 *  is not here: the control plane owns it and may reprice, so ask the catalogue
 *  when the number matters. */
export function isBillable(attr: CanonicalAttribute | string | undefined): boolean {
    const a = typeof attr === 'string' ? ATTRIBUTE_MAP[attr] : attr;
    return a?.marketplace?.billable === true;
}

/** The `<namespace>:<name>` spelling the marketplace prices this attribute
 *  under, or undefined when it sells no such disclosure. Never rebuild it as
 *  `privasys:${key}`: the namespace belongs to whichever provider sells the
 *  attribute, and an `_id` key is sold under the field the enclave meters. */
export function marketplaceKeyOf(attr: CanonicalAttribute | string | undefined): string | undefined {
    const a = typeof attr === 'string' ? ATTRIBUTE_MAP[attr] : attr;
    return a?.marketplace?.key;
}

/**
 * The pairs a relying party actually chooses between.
 *
 * `given_name` and `given_name_id` are the same fact at two trust levels and two
 * prices, and a picker that lists them as unrelated rows makes the choice look
 * like a duplicate rather than a decision. Returns the self-asserted key with
 * its government-backed twin, for the pairs where both exist.
 */
export function attributePairs(): { self: CanonicalAttribute; gov: CanonicalAttribute }[] {
    const out: { self: CanonicalAttribute; gov: CanonicalAttribute }[] = [];
    for (const a of CANONICAL_ATTRIBUTES) {
        const gov = a.govKey ? ATTRIBUTE_MAP[a.govKey] : undefined;
        if (gov) out.push({ self: a, gov });
    }
    return out;
}

/**
 * The attributes worth offering an integrator, newest spelling only.
 *
 * A key marked `supersededBy` still resolves and must never be removed, but
 * putting both spellings in a picker asks a developer to choose between two
 * names for one disclosure. They are hidden here and remain reachable by key.
 */
export function requestableAttributes(
    all: CanonicalAttribute[] = CANONICAL_ATTRIBUTES,
): CanonicalAttribute[] {
    return all.filter((a) => !a.supersededBy);
}

/**
 * Fetch the referential the IdP is serving right now.
 *
 * The bundled list is the one this SDK version was built against; the live
 * document is the one the IdP will actually honour, and between a new attribute
 * shipping and an integrator upgrading their dependency the two differ. Use this
 * when a picker should offer what the platform sells today rather than what this
 * bundle knew about. Everything else in this module works on either list, which
 * is why the accessors take an attribute as well as a key.
 */
export async function fetchAttributeReferential(
    issuerUrl = 'https://privasys.id',
): Promise<CanonicalAttribute[]> {
    const res = await fetch(`${issuerUrl.replace(/\/$/, '')}/referential/canonical-attributes.json`);
    if (!res.ok) throw new Error(`referential ${res.status}`);
    const doc = (await res.json()) as { attributes?: CanonicalAttribute[] };
    return doc.attributes ?? [];
}
