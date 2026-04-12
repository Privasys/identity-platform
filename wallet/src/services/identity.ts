// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Federated identity linking — OAuth 2.0 / OIDC flows for external providers.
 *
 * Uses expo-auth-session for the OAuth flow and expo-web-browser for the
 * system browser. The wallet links provider accounts for:
 * 1. Profile seeding (name, email, avatar)
 * 2. Account recovery (re-register FIDO2 after device loss)
 * 3. Platform API auth via Zitadel
 *
 * The linked identity is NOT used for enclave authentication — that's always FIDO2.
 */

import Constants from 'expo-constants';
import * as Crypto from 'expo-crypto';
import * as WebBrowser from 'expo-web-browser';

import type { LinkedProvider, ProfileAttribute } from '@/stores/profile';

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

/** Build the redirect URI from the app's configured scheme. */
function getRedirectUri(): string {
    const scheme = Constants.expoConfig?.scheme ?? 'privasys-wallet';
    return `${scheme}://auth/callback`;
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

    const redirectUri = getRedirectUri();

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

/**
 * Exchange an authorization code for tokens.
 */
export async function exchangeCode(
    config: ProviderConfig,
    code: string,
    codeVerifier: string
): Promise<TokenResponse> {
    const body = new URLSearchParams({
        client_id: config.clientId,
        code,
        redirect_uri: getRedirectUri(),
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
 */
export async function fetchUserInfo(
    config: ProviderConfig,
    accessToken: string
): Promise<ProviderUserInfo> {
    const response = await fetch(config.userinfoEndpoint, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/json'
        }
    });

    if (!response.ok) {
        throw new Error(`Userinfo request failed: ${response.status}`);
    }

    const data = await response.json();

    // Normalise across providers
    return {
        sub: data.sub || data.id?.toString() || '',
        name: data.name || data.displayName || data.login || undefined,
        email: data.email || undefined,
        picture: data.picture || data.avatar_url || undefined,
        locale: data.locale || undefined
    };
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

    // 3. Fetch user info
    const userInfo = await fetchUserInfo(config, tokens.access_token);

    // 4. Build LinkedProvider
    const provider: LinkedProvider = {
        provider: config.provider,
        displayName: config.displayName,
        sub: userInfo.sub,
        email: userInfo.email,
        linkedAt: Math.floor(Date.now() / 1000),
        refreshToken: tokens.refresh_token
    };

    // 5. Build seed attributes from provider data
    const seedAttributes: ProfileAttribute[] = [];
    if (userInfo.name) {
        seedAttributes.push({
            key: 'displayName',
            label: 'Display Name',
            value: userInfo.name,
            source: 'provider',
            sourceProvider: config.provider,
            verified: true
        });
    }
    if (userInfo.email) {
        seedAttributes.push({
            key: 'email',
            label: 'Email',
            value: userInfo.email,
            source: 'provider',
            sourceProvider: config.provider,
            verified: true
        });
    }
    if (userInfo.picture) {
        seedAttributes.push({
            key: 'avatarUri',
            label: 'Avatar',
            value: userInfo.picture,
            source: 'provider',
            sourceProvider: config.provider,
            verified: false
        });
    }

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
