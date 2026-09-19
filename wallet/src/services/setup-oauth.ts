// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The sign-in step of a service's setup: an OAuth consent at a provider,
 * run by the SERVICE, with the wallet holding the browser.
 *
 * The contract, from the wallet's side only:
 *
 * 1. The wallet opens `<start_url>?redirect_uri=<wallet scheme>://setup/callback&nonce=<n>`
 *    in an authentication session. The service builds the provider's
 *    authorisation URL itself (its client id, its PKCE verifier, its own
 *    https redirect) and sends the browser there.
 * 2. The provider comes back to the service. The service exchanges the code,
 *    keeps the tokens in memory under a one-time GRANT CODE, and redirects
 *    the browser to the wallet's redirect URI with `grant=<code>&nonce=<n>`.
 * 3. The wallet returns the grant code as the field's answer; the mint sends
 *    it in `setup`, the service redeems it (once, soon) and binds the tokens
 *    to the holder the mint authenticated. What the service wants the phone
 *    to hold comes back as `keep` and is sent as `setup.kept` next time.
 *
 * So the wallet never sees a provider token, never learns a client id, and
 * checks two things: the start URL is on the service's attested host, and the
 * nonce it sent is the nonce that came back.
 */

import Constants from 'expo-constants';
import * as WebBrowser from 'expo-web-browser';

import * as Crypto from 'expo-crypto';
import type { SetupOAuth } from '@/services/capability-setup';

/** A random correlation value the callback must echo. */
async function generateNonce(): Promise<string> {
    const bytes = await Crypto.getRandomBytesAsync(16);
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

export class SetupOAuthError extends Error {
    constructor(message: string, readonly cancelled = false) {
        super(message);
    }
}

/** The wallet's own callback for this step. One per app scheme. */
export function setupCallbackUri(): string {
    const scheme = Constants.expoConfig?.scheme ?? 'privasys-wallet';
    return `${scheme}://setup/callback`;
}

/** The start URL must sit on the service the wallet attested, over https. */
export function startUrlIsOn(startUrl: string, resourceHost: string): boolean {
    try {
        const u = new URL(startUrl);
        return u.protocol === 'https:' && u.hostname.toLowerCase() === resourceHost.toLowerCase();
    } catch {
        return false;
    }
}

/** Build the URL the browser opens: the service's start URL plus where to come back. */
export function startUrlWith(startUrl: string, redirectUri: string, nonce: string): string {
    const u = new URL(startUrl);
    u.searchParams.set('redirect_uri', redirectUri);
    u.searchParams.set('nonce', nonce);
    return u.toString();
}

/** Read the grant code out of the callback URL, checking the nonce. */
export function grantFromCallback(url: string, nonce: string): string {
    const cb = new URL(url);
    const error = cb.searchParams.get('error');
    const grant = cb.searchParams.get('grant') ?? '';
    if (error || !grant) {
        throw new SetupOAuthError(error || 'the sign-in did not complete');
    }
    if (cb.searchParams.get('nonce') !== nonce) {
        throw new SetupOAuthError('the sign-in came back for another request');
    }
    if (grant.length > 512 || !/^[A-Za-z0-9._~-]+$/.test(grant)) {
        throw new SetupOAuthError('the sign-in came back with something the wallet cannot use');
    }
    return grant;
}

/**
 * Run the sign-in and return the grant code for the field's answer.
 * `resourceHost` is the host the wallet attested for the resource service.
 */
export async function runSetupOAuth(oauth: SetupOAuth, resourceHost: string): Promise<string> {
    if (!startUrlIsOn(oauth.startUrl, resourceHost)) {
        throw new SetupOAuthError('the sign-in would start somewhere other than the service');
    }
    const nonce = await generateNonce();
    const redirectUri = setupCallbackUri();
    const result = await WebBrowser.openAuthSessionAsync(
        startUrlWith(oauth.startUrl, redirectUri, nonce),
        redirectUri,
    );
    if (result.type !== 'success' || !result.url) {
        throw new SetupOAuthError(
            result.type === 'cancel' || result.type === 'dismiss' ? 'cancelled' : 'the sign-in did not complete',
            result.type === 'cancel' || result.type === 'dismiss',
        );
    }
    return grantFromCallback(result.url, nonce);
}
