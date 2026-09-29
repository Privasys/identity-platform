// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * What a disclosure costs, and which section of a picker it belongs in.
 *
 * Prices are not in the referential. The referential says WHETHER a key is sold
 * (`marketplace.billable`) and under which `<namespace>:<name>`; the price itself
 * lives in the marketplace catalogue on the control plane, where a provider can
 * change it without an SDK release. These helpers join the two so every surface
 * shows the same number the same way.
 *
 * The platform keeps prices in credits, a million to the pound. That rate is
 * what every Privasys surface converts at, which is why it lives here once
 * instead of as a constant repeated in each front.
 */

import { isBillable, isGovVerified, marketplaceKeyOf, type CanonicalAttribute } from './attributes';

/** Credits in one pound sterling. */
export const CREDITS_PER_GBP = 1_000_000;

/** Marketplace key (`privasys:age_over_18`) to price in credits. */
export type AttributePrices = ReadonlyMap<string, number>;

/**
 * Credits as the pounds they are: "£0.01". Two decimals at least and up to four,
 * so a price under a penny still reads as a price rather than "£0.00".
 */
export function formatCredits(credits: number): string {
    return `£${(credits / CREDITS_PER_GBP).toLocaleString('en-GB', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 4,
    })}`;
}

/** The price of one attribute, or undefined when it is not sold or not yet known. */
export function priceOf(prices: AttributePrices | null | undefined, attr: CanonicalAttribute): number | undefined {
    if (!prices || !isBillable(attr)) return undefined;
    const key = marketplaceKeyOf(attr);
    return key === undefined ? undefined : prices.get(key);
}

/**
 * What one disclosure of everything in `chosen` costs. Undefined when a chosen
 * paid attribute has no known price: a partial sum would state a lower bill than
 * the real one, the one direction this must never be wrong in.
 */
export function disclosureCost(
    prices: AttributePrices | null | undefined,
    attrs: readonly CanonicalAttribute[],
    chosen: readonly string[],
): number | undefined {
    let total = 0;
    for (const key of chosen) {
        const a = attrs.find((x) => x.key === key);
        if (!a || !isBillable(a)) continue;
        const p = priceOf(prices, a);
        if (p === undefined) return undefined;
        total += p;
    }
    return total;
}

/**
 * Read the marketplace catalogue's prices. `apiBase` is the control plane (the
 * same base the auth config already names); `token` is the signed-in user's own
 * access token, since the catalogue sits behind authentication.
 */
export async function fetchAttributePrices(
    apiBase: string,
    token: string,
    signal?: AbortSignal,
): Promise<Map<string, number>> {
    const res = await fetch(`${apiBase.replace(/\/$/, '')}/api/v1/attributes`, {
        signal,
        headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`attribute catalogue: ${res.status}`);
    const doc = (await res.json()) as { attributes?: { key?: string; price_credits?: number }[] };
    const out = new Map<string, number>();
    for (const a of doc.attributes ?? []) {
        if (a.key && typeof a.price_credits === 'number') out.set(a.key, a.price_credits);
    }
    return out;
}

/**
 * Where an attribute sits in a picker. The assurance is stated once, by the
 * section, rather than repeated as a badge on every chip:
 *
 *   holder  what the holder supplies (typed, or imported from a provider)
 *   gov     certified from a government document, and free to request
 *   paid    sold: each disclosure is charged, and the chip carries the price
 *
 * Paid comes last and apart, because a recurring charge is the thing a person
 * choosing attributes most needs to notice and a mixed list is where it hides.
 */
export type AttributeSectionId = 'holder' | 'gov' | 'paid';

export interface AttributeSection {
    id: AttributeSectionId;
    attributes: CanonicalAttribute[];
}

export function attributeSections(attrs: readonly CanonicalAttribute[]): AttributeSection[] {
    const bucket = (a: CanonicalAttribute): AttributeSectionId =>
        isBillable(a) ? 'paid' : isGovVerified(a) ? 'gov' : 'holder';
    const order: AttributeSectionId[] = ['holder', 'gov', 'paid'];
    return order
        .map((id) => ({ id, attributes: attrs.filter((a) => bucket(a) === id) }))
        .filter((s) => s.attributes.length > 0);
}
