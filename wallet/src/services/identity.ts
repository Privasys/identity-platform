// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Federated identity linking — driven entirely through the Privasys IdP.
 *
 * The wallet does NOT hold provider OAuth client IDs or secrets and does not
 * talk to Google/Microsoft/GitHub/LinkedIn directly. Instead it reuses the
 * IdP's social federation (the same providers + held secrets the web auth SDK
 * uses) via the wallet-link flow:
 *
 *   1. open  GET /wallet/link?provider=&redirect_uri=&nonce=&code_challenge=
 *   2. IdP runs the upstream OAuth server-side and 302s back to the wallet
 *      custom scheme with a one-time result code
 *   3. GET /wallet/link/result?code=&code_verifier= returns the normalised
 *      canonical attributes (with verification status)
 *
 * One referential, one secret store. PKCE (S256) binds the result redemption to
 * this wallet instance so a hijacked deep link cannot redeem the code. No
 * provider tokens are stored — recovery uses the verified identity only.
 *
 * The linked identity is NOT used for enclave authentication — that's always FIDO2.
 */

import Constants from 'expo-constants';
import * as Crypto from 'expo-crypto';
import { File, Paths } from 'expo-file-system';
import * as WebBrowser from 'expo-web-browser';

import { attributeLabel } from '@/services/attributes';
import type { LinkedProvider, ProfileAttribute, VerificationRecord } from '@/stores/profile';

// Ensure web browser sessions are cleaned up on redirect
WebBrowser.maybeCompleteAuthSession();

/** Base URL of the Privasys IdP (matches recovery-api.ts / sessions-api.ts). */
const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** Userinfo distilled from a linked provider, for convenient profile seeding. */
export interface ProviderUserInfo {
    sub: string;
    name?: string;
    email?: string;
    picture?: string;
    locale?: string;
}

/**
 * Display metadata for the providers the IdP federates. This is presentation
 * only — there are no client IDs, secrets, or endpoints here. The IdP owns the
 * actual OAuth configuration; call `fetchAvailableProviders()` to learn which
 * are configured server-side.
 */
export const PROVIDERS: Record<string, { provider: string; displayName: string }> = {
    google: { provider: 'google', displayName: 'Google' },
    microsoft: { provider: 'microsoft', displayName: 'Microsoft' },
    github: { provider: 'github', displayName: 'GitHub' },
    linkedin: { provider: 'linkedin', displayName: 'LinkedIn' },
};

/** Shape of the wallet-link result returned by the IdP. */
interface WalletLinkResult {
    provider: string;
    sub: string;
    attributes: { key: string; value: string; verified: boolean }[];
}

/** Generate a cryptographically random nonce for CSRF correlation. */
async function generateNonce(): Promise<string> {
    const bytes = await Crypto.getRandomBytesAsync(16);
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/** Generate a PKCE code verifier and S256 challenge. */
async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
    const bytes = await Crypto.getRandomBytesAsync(32);
    const verifier = base64urlEncode(bytes);
    const digest = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        verifier,
        { encoding: Crypto.CryptoEncoding.BASE64 }
    );
    const challenge = digest.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { verifier, challenge };
}

function base64urlEncode(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Ask the IdP which social providers are actually configured server-side, so the
 * UI can show only working buttons (no "not configured" dead ends).
 */
export async function fetchAvailableProviders(): Promise<string[]> {
    try {
        const resp = await fetch(`${IDP_BASE}/auth/social/providers`, {
            headers: { Accept: 'application/json' },
        });
        if (!resp.ok) return [];
        const data: { providers?: string[] } = await resp.json();
        return data.providers ?? [];
    } catch {
        return [];
    }
}

/**
 * Download an avatar image from a remote URL and cache it locally.
 * Returns the local file URI. If the image is already cached, returns the
 * existing local URI without re-downloading.
 */
export async function downloadAndCacheAvatar(url: string): Promise<string> {
    const hash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        url,
    );
    const ext = url.match(/\.(png|gif|webp)/i)?.[1] ?? 'jpg';
    const destination = new File(Paths.cache, `avatar-${hash.substring(0, 16)}.${ext}`);

    if (destination.exists) return destination.uri;

    const downloaded = await File.downloadFileAsync(url, destination, { idempotent: true });
    return downloaded.uri;
}

/**
 * Link an external identity provider through the IdP and return the resulting
 * LinkedProvider, a distilled userInfo, and the seed ProfileAttributes (with
 * provenance + verification) to write into the local profile.
 */
export async function linkProviderViaIdP(providerKey: string): Promise<{
    provider: LinkedProvider;
    userInfo: ProviderUserInfo;
    seedAttributes: ProfileAttribute[];
}> {
    const displayName = PROVIDERS[providerKey]?.displayName ?? providerKey;

    const { verifier, challenge } = await generatePKCE();
    const nonce = await generateNonce();
    const scheme = Constants.expoConfig?.scheme ?? 'privasys-wallet';
    const redirectUri = `${scheme}://link/callback`;

    // 1. Open the IdP wallet-link flow in the system browser.
    const params = new URLSearchParams({
        provider: providerKey,
        redirect_uri: redirectUri,
        nonce,
        code_challenge: challenge,
        code_challenge_method: 'S256',
    });
    const result = await WebBrowser.openAuthSessionAsync(
        `${IDP_BASE}/wallet/link?${params.toString()}`,
        redirectUri,
    );

    if (result.type !== 'success' || !result.url) {
        throw new Error(result.type === 'cancel' ? 'Authentication cancelled' : 'Authentication failed');
    }

    const cb = new URL(result.url);
    const code = cb.searchParams.get('code');
    const returnedNonce = cb.searchParams.get('nonce');
    if (!code) {
        throw new Error(cb.searchParams.get('error') || 'No result code received');
    }
    if (returnedNonce !== nonce) {
        throw new Error('Nonce mismatch — possible CSRF attack');
    }

    // 2. Redeem the one-time code with the PKCE verifier.
    const resp = await fetch(
        `${IDP_BASE}/wallet/link/result?code=${encodeURIComponent(code)}&code_verifier=${encodeURIComponent(verifier)}`,
        { headers: { Accept: 'application/json' } },
    );
    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Link failed: ${resp.status} ${text}`);
    }
    const data: WalletLinkResult = await resp.json();

    // 3. Build seed attributes + distilled userInfo from the IdP result.
    const now = Math.floor(Date.now() / 1000);
    const userInfo: ProviderUserInfo = { sub: data.sub };
    const seedAttributes: ProfileAttribute[] = [];

    for (const a of data.attributes ?? []) {
        if (!a.value) continue;

        let value = a.value;
        if (a.key === 'picture') {
            // Cache the avatar locally so we don't depend on the provider after import.
            try {
                value = await downloadAndCacheAvatar(a.value);
            } catch {
                value = a.value; // fallback to remote URL
            }
            userInfo.picture = value;
        } else if (a.key === 'name') {
            userInfo.name = a.value;
        } else if (a.key === 'email') {
            userInfo.email = a.value;
        } else if (a.key === 'locale') {
            // Already normalised to a canonical BCP-47 tag by the IdP.
            userInfo.locale = a.value;
        }

        const verifications: VerificationRecord[] = a.verified
            ? [{
                  verifier: providerKey,
                  verifierDisplayName: displayName,
                  method: 'oidc_claim' as const,
                  assurance: 'provider' as const,
                  verifiedAt: now,
                  evidence: `${providerKey}:${a.key}_verified=true`,
              }]
            : [];

        seedAttributes.push({
            key: a.key,
            label: attributeLabel(a.key),
            value,
            source: 'provider',
            sourceProvider: providerKey,
            acquiredAt: now,
            updatedAt: now,
            verified: a.verified,
            verifications,
        });
    }

    const provider: LinkedProvider = {
        provider: providerKey,
        displayName,
        sub: data.sub,
        email: userInfo.email,
        linkedAt: now,
        // No provider refresh token stored — recovery uses verified identity only.
    };

    return { provider, userInfo, seedAttributes };
}
