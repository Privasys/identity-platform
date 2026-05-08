// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Federated identity linking — OAuth 2.0 / OIDC flows for external providers.
 *
 * Uses expo-auth-session for the OAuth flow and expo-web-browser for the
 * system browser. The wallet links provider accounts for:
 * 1. Profile seeding (name, email, avatar)
 * 2. Account recovery (re-register FIDO2 after device loss)
 * 3. Platform API auth via Privasys ID
 *
 * The linked identity is NOT used for enclave authentication — that's always FIDO2.
 */

import Constants from 'expo-constants';
import * as Crypto from 'expo-crypto';
import { File, Paths } from 'expo-file-system';
import * as WebBrowser from 'expo-web-browser';
import { Platform } from 'react-native';

import type { LinkedProvider, ProfileAttribute } from '@/stores/profile';
import { normalizeProviderClaims, claimsToProfileAttributes } from '@/services/attributes';

// Ensure web browser sessions are cleaned up on redirect
WebBrowser.maybeCompleteAuthSession();

/** Well-known OIDC provider configurations. */
export interface ProviderConfig {
    provider: string;
    displayName: string;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    userinfoEndpoint: string;
    clientId: string;
    scopes: string[];
    /** URL to revoke tokens (optional). */
    revokeEndpoint?: string;
}

/** Tokens returned from the OAuth exchange. */
interface TokenResponse {
    access_token: string;
    id_token?: string;
    refresh_token?: string;
    expires_in?: number;
    token_type: string;
}

/** Userinfo from the provider. */
export interface ProviderUserInfo {
    sub: string;
    name?: string;
    email?: string;
    picture?: string;
    locale?: string;
}

/**
 * Build the redirect URI for the OAuth callback.
 *
 * Google requires the reversed client ID as the URI scheme on iOS/Android.
 * Other providers use the app's configured custom scheme.
 */
function getRedirectUri(providerKey?: string): string {
    if (providerKey === 'google') {
        const clientId = getClientId('google');
        if (clientId) {
            // Google requires: com.googleusercontent.apps.{CLIENT_ID_PREFIX}:/oauthredirect
            const prefix = clientId.replace('.apps.googleusercontent.com', '');
            return `com.googleusercontent.apps.${prefix}:/oauthredirect`;
        }
    }
    const scheme = Constants.expoConfig?.scheme ?? 'privasys-wallet';
    return `${scheme}://auth/callback`;
}

/**
 * Resolve the OAuth client ID for a provider.
 * Google requires platform-specific client IDs (iOS vs Android use different
 * OAuth client types keyed to bundle ID / package name + signing cert).
 */
export function getClientId(providerKey: string): string {
    // IMPORTANT: Expo's Metro/Babel transform only inlines process.env.EXPO_PUBLIC_*
    // with static member access. Dynamic keys like process.env[`EXPO_PUBLIC_${x}`]
    // are NOT replaced and resolve to undefined at runtime.
    const clientIds: Record<string, string> = {
        google:
            Platform.OS === 'ios'
                ? (process.env.EXPO_PUBLIC_OAUTH_GOOGLE_CLIENT_ID_IOS ?? '')
                : (process.env.EXPO_PUBLIC_OAUTH_GOOGLE_CLIENT_ID_ANDROID ?? ''),
        microsoft: process.env.EXPO_PUBLIC_OAUTH_MICROSOFT_CLIENT_ID ?? '',
        github: process.env.EXPO_PUBLIC_OAUTH_GITHUB_CLIENT_ID ?? '',
        linkedin: process.env.EXPO_PUBLIC_OAUTH_LINKEDIN_CLIENT_ID ?? '',
    };
    return clientIds[providerKey] ?? '';
}

/**
 * Built-in provider configurations.
 * Client IDs are configured per-environment.
 */
export const PROVIDERS: Record<string, Omit<ProviderConfig, 'clientId'>> = {
    google: {
        provider: 'google',
        displayName: 'Google',
        authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenEndpoint: 'https://oauth2.googleapis.com/token',
        userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
        scopes: ['openid', 'profile', 'email']
    },
    microsoft: {
        provider: 'microsoft',
        displayName: 'Microsoft',
        authorizationEndpoint:
            'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        userinfoEndpoint: 'https://graph.microsoft.com/oidc/userinfo',
        scopes: ['openid', 'profile', 'email']
    },
    github: {
        provider: 'github',
        displayName: 'GitHub',
        authorizationEndpoint: 'https://github.com/login/oauth/authorize',
        tokenEndpoint: 'https://github.com/login/oauth/access_token',
        userinfoEndpoint: 'https://api.github.com/user',
        scopes: ['read:user', 'user:email']
    },
    linkedin: {
        provider: 'linkedin',
        displayName: 'LinkedIn',
        authorizationEndpoint: 'https://www.linkedin.com/oauth/v2/authorization',
        tokenEndpoint: 'https://www.linkedin.com/oauth/v2/accessToken',
        userinfoEndpoint: 'https://api.linkedin.com/v2/userinfo',
        scopes: ['openid', 'profile', 'email']
    }
};

/** Generate a cryptographically random state parameter for CSRF protection. */
async function generateState(): Promise<string> {
    const bytes = await Crypto.getRandomBytesAsync(32);
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/** Generate a PKCE code verifier and challenge. */
async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
    const bytes = await Crypto.getRandomBytesAsync(32);
    const verifier = base64urlEncode(bytes);
    const digest = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        verifier,
        { encoding: Crypto.CryptoEncoding.BASE64 }
    );
    // Convert base64 to base64url
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
 * Start the OAuth 2.0 authorization flow for a provider.
 * Opens the system browser, returns the authorization code.
 */
export async function startAuthFlow(config: ProviderConfig): Promise<{
    code: string;
    codeVerifier: string;
}> {
    const state = await generateState();
    const { verifier, challenge } = await generatePKCE();

    const redirectUri = getRedirectUri(config.provider);

    const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: config.scopes.join(' '),
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256'
    });

    const authUrl = `${config.authorizationEndpoint}?${params.toString()}`;

    const result = await WebBrowser.openAuthSessionAsync(authUrl, redirectUri);

    if (result.type !== 'success' || !result.url) {
        throw new Error(result.type === 'cancel' ? 'Authentication cancelled' : 'Authentication failed');
    }

    const url = new URL(result.url);
    const code = url.searchParams.get('code');
    const returnedState = url.searchParams.get('state');

    if (!code) {
        const error = url.searchParams.get('error_description') || url.searchParams.get('error');
        throw new Error(error || 'No authorization code received');
    }

    if (returnedState !== state) {
        throw new Error('State mismatch — possible CSRF attack');
    }

    return { code, codeVerifier: verifier };
}

/** Providers that require a server-side secret for token exchange. */
const PROXIED_PROVIDERS = new Set(['github', 'linkedin']);

/** Base URL for the broker's HTTPS endpoints. */
const BROKER_BASE = 'https://relay.privasys.org';

/**
 * Exchange an authorization code for tokens.
 * For providers that require a client_secret (GitHub, LinkedIn), the exchange
 * is proxied through the broker which holds the secrets server-side.
 */
export async function exchangeCode(
    config: ProviderConfig,
    code: string,
    codeVerifier: string
): Promise<TokenResponse> {
    if (PROXIED_PROVIDERS.has(config.provider)) {
        // Route through broker proxy — secret is injected server-side
        const response = await fetch(`${BROKER_BASE}/oauth/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: JSON.stringify({
                provider: config.provider,
                code,
                code_verifier: codeVerifier,
                redirect_uri: getRedirectUri(config.provider),
            })
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Token exchange failed: ${response.status} ${text}`);
        }

        return response.json();
    }

    // Direct exchange (Google, Microsoft — support PKCE without secret)
    const body = new URLSearchParams({
        client_id: config.clientId,
        code,
        redirect_uri: getRedirectUri(config.provider),
        grant_type: 'authorization_code',
        code_verifier: codeVerifier
    });

    const response = await fetch(config.tokenEndpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json'
        },
        body: body.toString()
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Token exchange failed: ${response.status} ${text}`);
    }

    return response.json();
}

/**
 * Fetch user info from the provider's userinfo endpoint.
 * Returns normalised canonical claims AND the raw provider response
 * (needed for verification claim extraction like email_verified).
 */
export async function fetchUserInfo(
    config: ProviderConfig,
    accessToken: string
): Promise<{ userInfo: ProviderUserInfo; raw: Record<string, unknown> }> {
    const response = await fetch(config.userinfoEndpoint, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/json'
        }
    });

    if (!response.ok) {
        throw new Error(`Userinfo request failed: ${response.status}`);
    }

    const raw: Record<string, unknown> = await response.json();

    // Normalise provider-specific claims into our canonical attribute names.
    const normalised = normalizeProviderClaims(config.provider, raw);

    const userInfo: ProviderUserInfo = {
        sub: normalised.sub || String(raw.sub ?? raw.id ?? ''),
        name: normalised.name || undefined,
        email: normalised.email || undefined,
        picture: normalised.picture || undefined,
        locale: normalised.locale || undefined
    };

    return { userInfo, raw };
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
 * Complete the full link flow: auth → token exchange → userinfo → LinkedProvider.
 */
export async function linkIdentityProvider(config: ProviderConfig): Promise<{
    provider: LinkedProvider;
    userInfo: ProviderUserInfo;
    seedAttributes: ProfileAttribute[];
}> {
    // 1. Authorization flow
    const { code, codeVerifier } = await startAuthFlow(config);

    // 2. Token exchange
    const tokens = await exchangeCode(config, code, codeVerifier);

    // 3. Fetch user info (normalised + raw for verification claim extraction)
    const { userInfo, raw } = await fetchUserInfo(config, tokens.access_token);

    // 4. Build LinkedProvider
    const provider: LinkedProvider = {
        provider: config.provider,
        displayName: config.displayName,
        sub: userInfo.sub,
        email: userInfo.email,
        linkedAt: Math.floor(Date.now() / 1000),
        refreshToken: tokens.refresh_token
    };

    // 5. Build seed attributes from normalised provider data, passing raw
    //    claims so verification status (email_verified, etc.) is extracted.
    const normalisedClaims: Record<string, string> = {};
    if (userInfo.name) normalisedClaims.name = userInfo.name;
    if (userInfo.email) normalisedClaims.email = userInfo.email;
    if (userInfo.picture) {
        // Download avatar locally so we don't depend on the provider after import
        try {
            normalisedClaims.picture = await downloadAndCacheAvatar(userInfo.picture);
        } catch {
            normalisedClaims.picture = userInfo.picture; // fallback to remote URL
        }
    }
    if (userInfo.locale) normalisedClaims.locale = userInfo.locale;

    const seedAttributes = claimsToProfileAttributes(normalisedClaims, config.provider, raw);

    return { provider, userInfo, seedAttributes };
}

/**
 * Create a ProviderConfig for a custom OIDC provider by discovering endpoints.
 */
export async function discoverOIDCProvider(
    issuerUrl: string,
    clientId: string
): Promise<ProviderConfig> {
    const wellKnown = issuerUrl.replace(/\/+$/, '') + '/.well-known/openid-configuration';
    const response = await fetch(wellKnown);
    if (!response.ok) {
        throw new Error(`OIDC discovery failed: ${response.status}`);
    }
    const config = await response.json();

    return {
        provider: issuerUrl,
        displayName: config.issuer || issuerUrl,
        authorizationEndpoint: config.authorization_endpoint,
        tokenEndpoint: config.token_endpoint,
        userinfoEndpoint: config.userinfo_endpoint,
        clientId,
        scopes: ['openid', 'profile', 'email'],
        revokeEndpoint: config.revocation_endpoint
    };
}
