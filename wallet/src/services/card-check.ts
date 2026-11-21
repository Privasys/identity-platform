// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A billing address confirmed by the holder's card's bank.
 *
 * A £0 card check on the payment provider's hosted card page (the card form
 * belongs in a browser, never in the wallet): the bank confirms, or not, the
 * first line and the postcode the holder typed. The wallet then has the
 * Privasys Attribute Verifier sign the fields that passed, and keeps the proof
 * with the check's result.
 *
 *  1. Start the check on the control plane with the holder commitment (a
 *     fresh salt: no two checks can be linked), a PKCE challenge and the
 *     wallet's return link, and open the provider's page it answers with in
 *     the system's sign-in browser. No privasys.id page, so no second sign-in.
 *  2. The control plane hands back a one-time code; the wallet claims the
 *     result with the PKCE verifier, so no other app that caught the redirect
 *     can.
 *  3. The verifier asks the back office about the check and signs the passed
 *     fields as the canonical "address" (street_address, postal_code). The
 *     card's brand and country are display data in its label.
 *
 * The result's check_id proves the check is the holder's: it is kept only on
 * the attribute (encrypted in the device sync and the profile copy), never
 * logged.
 */

import Constants from 'expo-constants';
import * as Crypto from 'expo-crypto';
import * as WebBrowser from 'expo-web-browser';

import { attest, newCommitment, type AttributeProof } from '@/services/attribute-verifier';
import { thisDeviceBinding } from '@/services/attribute-proofs';
import { getPlatformToken } from '@/services/platform-token';
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
    const token = await getPlatformToken();
    const res = await fetch(`${API_BASE.replace(/\/+$/, '')}/api/v1/billing/address-checks/start`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ holder_binding: commitment, code_challenge: challenge, return: returnUrl }),
    });
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
    if (result.checks.line1 !== 'pass' && result.checks.postal_code !== 'pass') {
        throw new CardCheckError('nothing-confirmed', 'the bank confirmed neither the address nor the postcode');
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
        throw new CardCheckError('unverified', e?.message ?? 'the verifier could not sign the address');
    }
    const proof = proofs.find((p) => p.attr === 'address');
    if (!proof) throw new CardCheckError('unverified', 'the verifier signed no address');

    const value = JSON.stringify(proof.value);
    const now = Math.floor(Date.now() / 1000);
    const attr: ProfileAttribute = {
        key: 'address',
        label: 'Address',
        value,
        source: 'provider',
        sourceProvider: 'card_bank',
        acquiredAt: now,
        updatedAt: now,
        verified: proof.method === 'proven',
        verifications: [
            {
                verifier: proof.source,
                verifierDisplayName: 'card_bank',
                method: 'card_check',
                assurance: proof.method === 'proven' ? 'provider' : 'none',
                verifiedAt: now,
                evidence: `verifier:${proof.source}:${proof.method}`,
                proof: proof.proof,
                proofDevice: await thisDeviceBinding(),
                proofSalt: salt,
                proofMaterial: { kind: 'card_check', data: { ...material, label: proof.label } },
            },
        ],
    };
    // An address is single-valued: a different one already there is replaced
    // by the one the holder has just typed and their bank has confirmed.
    const store = useProfileStore.getState();
    const merged = store.mergeAttribute(attr, false);
    if (merged.status === 'conflict') store.resolveConflict(merged.existing, merged.incoming, 'replace');
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
function countryFlag(code: string): string {
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
    if (brand && country) return t('cardCheck.confirmedByCard', { card: `${brand} ${country}` });
    if (brand || country) return t('cardCheck.confirmedByCard', { card: brand ?? country });
    return t('cardCheck.confirmedByBank');
}
