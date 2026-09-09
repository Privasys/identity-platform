// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Spend-consent API client — the IdP's `/spend/consents` endpoints.
 *
 * A spend consent is the holder's standing permission for ONE app to spend
 * their platform credits on their behalf (inference, priced tools), under a
 * monthly cap. The app is identified by its attested app id (OID 3.6, undashed
 * hex), the same identity the approval screen verified. The IdP backs each
 * consent with a session row, so withdrawing it lands on the revoked-session
 * feed every service already polls and takes effect within a minute.
 *
 * Auth: the short-lived wallet session token (`Bearer wallet:<token>`), the
 * same credential the sessions API uses.
 */

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** 1 credit = £0.000001 (pricing-plan §4.1). */
export const CREDITS_PER_GBP = 1_000_000;

export interface SpendConsent {
    /** Undashed hex app id (OID 3.6), or an OIDC client id for non-enclave apps. */
    app_id: string;
    app_host?: string;
    app_name?: string;
    /** Credits per calendar month; 0 = no cap. */
    cap: number;
    /** The backing IdP session id (revocation handle). */
    sid: string;
    created_at: string;
    updated_at: string;
}

function walletAuth(walletSessionToken: string): HeadersInit {
    return { Authorization: `Bearer wallet:${walletSessionToken}` };
}

async function idpFetch<T>(path: string, init: RequestInit): Promise<T> {
    const res = await fetch(`${IDP_BASE}${path}`, {
        ...init,
        headers: { 'Content-Type': 'application/json', ...init.headers },
    });
    if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(body.error || `Request failed: ${res.status}`);
    }
    if (res.status === 204) return undefined as T;
    return res.json() as Promise<T>;
}

/** Record (or renew) the holder's consent for `appId` to spend under `cap`
 *  credits per month (0 = no cap). Idempotent: a live consent keeps its
 *  session and only the cap moves. */
export async function grantSpendConsent(
    walletSessionToken: string,
    appId: string,
    cap: number,
    display?: { appHost?: string; appName?: string },
): Promise<SpendConsent> {
    return idpFetch<SpendConsent>('/spend/consents', {
        method: 'POST',
        headers: walletAuth(walletSessionToken),
        body: JSON.stringify({
            app_id: appId,
            cap: Math.max(0, Math.floor(cap)),
            app_host: display?.appHost,
            app_name: display?.appName,
        }),
    });
}

/** The holder's live consents. */
export async function listSpendConsents(walletSessionToken: string): Promise<SpendConsent[]> {
    const res = await idpFetch<{ consents: SpendConsent[] }>('/spend/consents', {
        method: 'GET',
        headers: walletAuth(walletSessionToken),
    });
    return res.consents ?? [];
}

/** The holder's live consent for one app, or null. */
export async function getSpendConsent(walletSessionToken: string, appId: string): Promise<SpendConsent | null> {
    try {
        return await idpFetch<SpendConsent>(`/spend/consents/${encodeURIComponent(appId)}`, {
            method: 'GET',
            headers: walletAuth(walletSessionToken),
        });
    } catch (e) {
        if (e instanceof Error && /no consent/i.test(e.message)) return null;
        throw e;
    }
}

/** Withdraw the consent: the app can no longer spend for the holder. */
export async function revokeSpendConsent(walletSessionToken: string, appId: string): Promise<void> {
    await idpFetch<unknown>(`/spend/consents/${encodeURIComponent(appId)}`, {
        method: 'DELETE',
        headers: walletAuth(walletSessionToken),
    });
}

/** Render a cap for the consent row ("£5.00 / month", or "no cap"). */
export function formatCap(cap: number, noCapLabel: string): string {
    if (!cap) return noCapLabel;
    return `£${(cap / CREDITS_PER_GBP).toLocaleString('en-GB', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
    })}`;
}
