// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A billing address confirmed by the holder's card's bank.
 *
 * A £0 card check on the payment provider's hosted card page (the card form
 * belongs in a browser, never in the wallet): the bank confirms, or not, the
 * first line and the postcode the holder typed. Only when it confirms both
 * does the wallet have the Privasys Attribute Verifier sign the address, and
 * keep the proof with the check's result: a postcode alone can match an old
 * address the bank still holds.
 *
 *  1. Start the check on the control plane with the holder commitment (a
 *     fresh salt: no two checks can be linked), a PKCE challenge and the
 *     wallet's return link, and open the provider's page it answers with in
 *     the system's sign-in browser. No privasys.id page, so no second sign-in.
 *  2. The control plane hands back a one-time code; the wallet claims the
 *     result with the PKCE verifier, so no other app that caught the redirect
 *     can.
 *  3. The verifier asks the back office about the check and, on a full
 *     match, signs the canonical "address" (street_address, postal_code), a
 *     billing address. The card's brand and country are display data in its
 *     label.
 *
 * The result's check_id proves the check is the holder's: it is kept only on
 * the attribute (encrypted in the device sync and the profile copy), never
 * logged.
 */

import Constants from 'expo-constants';
import * as Crypto from 'expo-crypto';
import * as WebBrowser from 'expo-web-browser';

import { attest, AttributeVerifierError, newCommitment, type AttributeProof } from '@/services/attribute-verifier';
import { thisDeviceBinding } from '@/services/attribute-proofs';
import { attributeLabel } from '@/services/attributes';
import { callWithPlatformToken } from '@/services/platform-token';
import { useProfileStore, type ProfileAttribute } from '@/stores/profile';
import { bytesToBase64url } from '@/utils/encoding';

/** The control plane the check's result is claimed from: the test one for preview builds. */
const API_BASE =
    process.env.EXPO_PUBLIC_ATTRIBUTE_VERIFIER_PLATFORM_URL ??
    process.env.EXPO_PUBLIC_PLATFORM_API_URL ??
    'https://api.developer.privasys.org';

export type CardCheckFailure = 'cancelled' | 'failed' | 'nothing-confirmed' | 'unverified';

export class CardCheckError extends Error {
    constructor(
        readonly reason: CardCheckFailure,
        message: string,
    ) {
        super(message);
    }
}

/** What the back office returns for a check. */
interface CheckResult {
    check_id: string;
    line1: string;
    postal_code: string;
    country: string;
    checks: { line1: string; postal_code: string };
    card_brand: string | null;
    card_country: string | null;
    checked_at: string;
    holder_binding: string;
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
    const verifier = bytesToBase64url(new Uint8Array(await Crypto.getRandomBytesAsync(32)));
    const digest = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, verifier, {
        encoding: Crypto.CryptoEncoding.BASE64,
    });
    return { verifier, challenge: digest.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') };
}

/**
 * Start the check on the control plane, which answers with the payment
 * provider's hosted card page. Opened in the system's sign-in browser (never a
 * view inside the wallet): no privasys.id page, so no second sign-in.
 */
async function startCheck(commitment: string, challenge: string, returnUrl: string): Promise<string> {
    const called = await callWithPlatformToken(
        (token) =>
            fetch(`${API_BASE.replace(/\/+$/, '')}/api/v1/billing/address-checks/start`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ holder_binding: commitment, code_challenge: challenge, return: returnUrl }),
            }),
        { interactive: true },
    );
    if (!called) throw new CardCheckError('failed', 'no platform token');
    const { res } = called;
    if (!res.ok) throw new CardCheckError('failed', `the card check could not start (HTTP ${res.status})`);
    const j = (await res.json()) as { checkout_url?: string; url?: string };
    const url = j.checkout_url ?? j.url;
    if (!url || !/^https:\/\//.test(url)) throw new CardCheckError('failed', 'the card check returned no page');
    return url;
}

/** Run the check on the provider's page and claim its result. */
async function runCheck(commitment: string): Promise<CheckResult> {
    const { verifier, challenge } = await pkce();
    const scheme = Constants.expoConfig?.scheme ?? 'privasys-wallet';
    const returnUrl = `${scheme}://card-check`;
    const checkoutUrl = await startCheck(commitment, challenge, returnUrl);

    const r = await WebBrowser.openAuthSessionAsync(checkoutUrl, returnUrl);
    if (r.type !== 'success' || !r.url) throw new CardCheckError('cancelled', 'the card check was closed');
    const back = new URL(r.url);
    const error = back.searchParams.get('error');
    if (error) throw new CardCheckError(error === 'cancelled' ? 'cancelled' : 'failed', `the card check ended: ${error}`);
    const code = back.searchParams.get('code');
    if (!code) throw new CardCheckError('failed', 'the card check returned no code');

    const res = await fetch(`${API_BASE.replace(/\/+$/, '')}/api/v1/billing/address-checks/claim`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, code_verifier: verifier }),
    });
    if (!res.ok) throw new CardCheckError('failed', `the check's result could not be claimed (HTTP ${res.status})`);
    return (await res.json()) as CheckResult;
}

/**
 * Check a billing address with the holder's card, and keep what the bank
 * confirmed as the verified "address". Returns the proof.
 */
export async function checkAddressWithCard(): Promise<AttributeProof> {
    const { salt, commitment } = newCommitment();
    const result = await runCheck(commitment);
    // An address is confirmed whole or not at all: a postcode alone can match
    // an old address the bank still holds (autofill offers old ones too).
    if (result.checks.line1 !== 'pass' || result.checks.postal_code !== 'pass') {
        throw new CardCheckError('nothing-confirmed', 'the bank did not confirm the full address');
    }
    const material = {
        check_id: result.check_id,
        line1: result.line1,
        postal_code: result.postal_code,
        country: result.country,
    };
    let proofs: AttributeProof[];
    try {
        proofs = await attest('card_check', material, salt);
    } catch (e: any) {
        // 422: the verifier's own reading of the check is not a full match.
        if (e instanceof AttributeVerifierError && e.status === 422) {
            throw new CardCheckError('nothing-confirmed', 'the bank did not confirm the full address');
        }
        throw new CardCheckError('unverified', e?.message ?? 'the verifier could not sign the address');
    }
    const proof = proofs.find((p) => p.attr === 'address');
    if (!proof) throw new CardCheckError('unverified', 'the verifier signed no address');

    const device = await thisDeviceBinding();
    const now = Math.floor(Date.now() / 1000);
    const keep = (p: AttributeProof, label: string, value: string) => {
        const attr: ProfileAttribute = {
            key: p.attr,
            label,
            value,
            source: 'provider',
            sourceProvider: 'card_bank',
            acquiredAt: now,
            updatedAt: now,
            verified: p.method === 'proven',
            verifications: [
                {
                    verifier: p.source,
                    verifierDisplayName: 'card_bank',
                    method: 'card_check',
                    assurance: p.method === 'proven' ? 'provider' : 'none',
                    verifiedAt: now,
                    evidence: `verifier:${p.source}:${p.method}`,
                    proof: p.proof,
                    proofDevice: device,
                    proofSalt: salt,
                    proofMaterial: { kind: 'card_check', data: { ...material, label: p.label } },
                },
            ],
        };
        // Single-valued: a different value already there is replaced by the
        // one the holder has just typed and their bank has confirmed.
        const store = useProfileStore.getState();
        const merged = store.mergeAttribute(attr, false);
        if (merged.status === 'conflict') store.resolveConflict(merged.existing, merged.incoming, 'replace');
    };
    keep(proof, attributeLabel('address'), JSON.stringify(proof.value));
    // The billing country, signed on its own so it can be shared without the
    // address: only on a full match, and when the card's country is the one
    // the holder typed (the verifier's rule).
    const country = proofs.find((p) => p.attr === 'billing_country');
    if (country && typeof country.value === 'string') {
        keep(country, attributeLabel('billing_country'), country.value.toUpperCase());
    }
    return proof;
}

/** An address attribute's value as one line: "1 High Street, AB1 2CD". */
export function formatAddress(value: string): string {
    try {
        const a = JSON.parse(value) as Record<string, string | undefined>;
        if (a.formatted) return a.formatted;
        return [a.street_address, a.locality, a.region, a.postal_code, a.country].filter(Boolean).join(', ');
    } catch {
        return value;
    }
}

const BRANDS: Record<string, string> = {
    visa: 'Visa',
    mastercard: 'Mastercard',
    amex: 'American Express',
    discover: 'Discover',
    diners: 'Diners Club',
    jcb: 'JCB',
    unionpay: 'UnionPay',
    cartes_bancaires: 'Cartes Bancaires',
};

/**
 * A country as its flag: the same in every language, where a name would need
 * translating and the phone's JavaScript engine has no country names (it
 * showed "GB"). Anything not a two-letter code is shown as it is.
 */
export function countryFlag(code: string): string {
    const c = code.trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(c)) return c;
    return String.fromCodePoint(...[...c].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}

/**
 * Who confirmed a card-checked address, from the proof's label: the card's
 * brand and country when the bank gave them, never the payment provider.
 * `t` is the screen's translate function.
 */
export function cardBankSource(
    attr: ProfileAttribute,
    t: (key: string, opts?: Record<string, unknown>) => string,
    locale: string,
): string {
    const label = attr.verifications?.find((v) => v.proofMaterial?.kind === 'card_check')?.proofMaterial?.data?.label as
        | { brand?: string | null; country?: string | null }
        | undefined;
    const brand = label?.brand ? BRANDS[label.brand.toLowerCase()] ?? label.brand : null;
    const country = label?.country ? countryFlag(label.country) : null;
    // The billing country is its own statement, shared without the address.
    const [byCard, byBank] =
        attr.key === 'billing_country'
            ? ['cardCheck.countryConfirmedByCard', 'cardCheck.countryConfirmedByBank']
            : ['cardCheck.confirmedByCard', 'cardCheck.confirmedByBank'];
    if (brand && country) return t(byCard, { card: `${brand} ${country}` });
    if (brand || country) return t(byCard, { card: brand ?? country });
    return t(byBank);
}
