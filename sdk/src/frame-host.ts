// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Frame host — runs inside the privasys.id/auth/ iframe.
 *
 * Listens for postMessage from the parent page, instantiates the AuthUI
 * to run the authentication ceremony, and relays results back via
 * postMessage. Sessions are stored in privasys.id's localStorage so
 * they persist across adopter sites.
 *
 * Sessions have a 15-minute client-side TTL. The frame host automatically
 * renews sessions via OIDC refresh_token grant before the TTL expires.
 * No push notification or wallet involvement is needed for renewal —
 * only the initial login requires the wallet.
 */

import { AuthUI } from './ui';
import type { AuthUIConfig, SignInResult } from './ui';
import { SessionManager } from './session';
import type { AuthSession } from './types';

const sessions = new SessionManager();

let activeUI: AuthUI | null = null;

// ── Session renewal (OIDC refresh_token) ────────────────────────────────

const RENEWAL_MS = 13 * 60 * 1000; // Renew at 13 min (before 15-min TTL)

const renewalTimers = new Map<string, ReturnType<typeof setTimeout>>();

function cancelRenewal(rpId: string): void {
    const timer = renewalTimers.get(rpId);
    if (timer) {
        clearTimeout(timer);
        renewalTimers.delete(rpId);
    }
}

function scheduleRenewal(session: AuthSession, parentOrigin: string): void {
    cancelRenewal(session.rpId);

    if (!session.refreshToken || !session.clientId) return;

    const timer = setTimeout(async () => {
        renewalTimers.delete(session.rpId);

        const current = sessions.get(session.rpId);
        if (!current?.refreshToken || !current?.clientId) return;

        try {
            await renewSession(current, parentOrigin);
            const updated = sessions.get(session.rpId);
            if (updated) scheduleRenewal(updated, parentOrigin);
        } catch (err) {
            console.warn('[frame-host] renewal failed, expiring session:', err);
            sessions.remove(session.rpId);
            window.parent.postMessage(
                { type: 'privasys:session-expired', rpId: session.rpId },
                parentOrigin,
            );
        }
    }, RENEWAL_MS);

    renewalTimers.set(session.rpId, timer);
}

/**
 * Renew a session by calling the IdP's OIDC refresh_token grant.
 * No push notification or wallet involvement — just a single HTTP call.
 */
async function renewSession(session: AuthSession, parentOrigin: string, notify = true): Promise<void> {
    const idpBase = globalThis.location.origin;

    const resp = await fetch(`${idpBase}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: session.refreshToken!,
            client_id: session.clientId!,
        }),
    });

    if (!resp.ok) {
        const body = await resp.json().catch(() => ({ error: resp.statusText }));
        throw new Error(body.error_description || body.error || `Refresh failed: ${resp.status}`);
    }

    const tokens = await resp.json();

    // Update session with new tokens (refresh token is rotated).
    sessions.store({
        ...session,
        token: tokens.access_token,
        refreshToken: tokens.refresh_token,
        authenticatedAt: Date.now(),
    });

    // Notify parent — skipped during check-session inline renewal to avoid
    // a double-message race (session-renewed before session response).
    if (notify) {
        window.parent.postMessage(
            {
                type: 'privasys:session-renewed',
                rpId: session.rpId,
                accessToken: tokens.access_token,
            },
            parentOrigin,
        );
    }
}

// ── OIDC PKCE helpers ───────────────────────────────────────────────────

/** Check whether an access token's exp claim is within a safety margin. */
function isTokenExpired(token: string, marginMs = 30_000): boolean {
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (typeof payload.exp !== 'number') return false;
        return payload.exp * 1000 - marginMs < Date.now();
    } catch {
        return false;
    }
}

async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    const codeVerifier = Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    return { codeVerifier, codeChallenge };
}

/** Poll the IdP session status until auth code is available or timeout. */
async function pollSessionStatus(pollUrl: string, timeoutMs = 120_000): Promise<string> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const resp = await fetch(pollUrl);
        if (!resp.ok) throw new Error(`poll failed: ${resp.status}`);
        const data = await resp.json();
        if (data.authenticated && data.redirect_uri) {
            const url = new URL(data.redirect_uri, globalThis.location.origin);
            const code = url.searchParams.get('code');
            if (code) return code;
        }
        await new Promise((r) => setTimeout(r, 1500));
    }
    throw new Error('OIDC session timed out');
}

/** Complete an OIDC session directly (after relay/social auth) and get the auth code. */
async function completeSession(
    idpBase: string,
    sessionId: string,
    attributes?: Record<string, string>,
): Promise<string> {
    const resp = await fetch(`${idpBase}/session/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            session_id: sessionId,
            user_id: attributes?.sub || '',
            attributes: attributes || {},
        }),
    });
    if (!resp.ok) {
        const body = await resp.json().catch(() => ({ error: resp.statusText }));
        throw new Error(body.error_description || body.error || `Session complete failed: ${resp.status}`);
    }
    const data = await resp.json();
    if (!data.code) throw new Error('No authorization code returned');
    return data.code;
}

/** Exchange an authorization code for tokens via the IdP /token endpoint. */

/** Exchange an authorization code for tokens via the IdP /token endpoint. */
async function exchangeCode(
    idpBase: string,
    code: string,
    clientId: string,
    codeVerifier: string,
): Promise<{ access_token: string; refresh_token?: string; expires_in: number }> {
    const resp = await fetch(`${idpBase}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: clientId,
            code_verifier: codeVerifier,
        }),
    });
    if (!resp.ok) {
        const body = await resp.json().catch(() => ({ error: resp.statusText }));
        throw new Error(body.error_description || body.error || `Token exchange failed: ${resp.status}`);
    }
    return resp.json();
}

// ── Message handler ─────────────────────────────────────────────────────

window.addEventListener('message', async (e: MessageEvent) => {
    const data = e.data;
    if (!data || typeof data.type !== 'string') return;

    if (data.type === 'privasys:init') {
        const config: AuthUIConfig & { clientId?: string; scope?: string | string[] } = data.config;
        const parentOrigin = e.origin;

        // Tear down any previous UI
        if (activeUI) {
            activeUI.destroy();
            activeUI = null;
        }

        // IdP base URL (same origin as this iframe).
        const idpBase = globalThis.location.origin;
        const clientId = config.clientId;

        // OIDC PKCE mode: create an OIDC session, authenticate, exchange for JWT.
        if (clientId) {
            try {
                // 1. Generate PKCE code_verifier + code_challenge.
                const { codeVerifier, codeChallenge } = await generatePKCE();

                // 2. Create OIDC session via JSON authorize.
                const authorizeUrl = new URL('/authorize', idpBase);
                authorizeUrl.searchParams.set('client_id', clientId);
                authorizeUrl.searchParams.set('response_type', 'code');
                authorizeUrl.searchParams.set('code_challenge', codeChallenge);
                authorizeUrl.searchParams.set('code_challenge_method', 'S256');
                const scopeStr = Array.isArray(config.scope) ? config.scope.join(' ') : (config.scope || 'openid offline_access');
                authorizeUrl.searchParams.set('scope', scopeStr);
                authorizeUrl.searchParams.set('response_mode', 'json');
                const authResp = await fetch(authorizeUrl.toString(), {
                    headers: { Accept: 'application/json' },
                });
                if (!authResp.ok) {
                    const body = await authResp.json().catch(() => ({ error: authResp.statusText }));
                    throw new Error(body.error_description || body.error || `Authorize failed: ${authResp.status}`);
                }
                const authData = await authResp.json();
                const oidcSessionId: string = authData.session_id;
                const pollUrl: string = authData.poll_url;
                const requestedAttributes: string[] | undefined = authData.requested_attributes;

                // 3. Fetch available social providers.
                let socialProviders: string[] = [];
                try {
                    const provResp = await fetch(`${idpBase}/auth/social/providers`);
                    if (provResp.ok) {
                        const provData = await provResp.json();
                        socialProviders = provData.providers ?? [];
                    }
                } catch { /* social not available, that's fine */ }

                // 4. Launch AuthUI with the OIDC session_id so QR/passkey link
                //    to the OIDC session. Use the iframe origin as apiBase for
                //    FIDO2 passkey calls (they go to the IdP, not the mgmt service).
                const pushToken = sessions.findPushToken();
                const deviceTrusted = !!sessions.getDeviceHint();

                // Social auth handler: opens a popup to the IdP's social redirect,
                // then waits for the callback page to postMessage back.
                const onSocialAuth = (provider: string): Promise<void> => {
                    return new Promise<void>((resolve, reject) => {
                        const w = 500, h = 650;
                        const left = window.screenX + (window.innerWidth - w) / 2;
                        const top = window.screenY + (window.innerHeight - h) / 2;
                        const popupUrl = `${idpBase}/auth/social?provider=${encodeURIComponent(provider)}&session_id=${encodeURIComponent(oidcSessionId)}`;
                        const popup = window.open(popupUrl, 'privasys-social', `width=${w},height=${h},left=${left},top=${top}`);

                        if (!popup) {
                            reject(new Error('Popup blocked — please allow popups for this site'));
                            return;
                        }

                        const cleanup = () => {
                            window.removeEventListener('message', onMessage);
                            clearInterval(pollClosed);
                        };

                        const onMessage = (ev: MessageEvent) => {
                            if (ev.source !== popup) return;
                            if (ev.data?.type === 'privasys:social-complete') {
                                cleanup();
                                popup.close();
                                resolve();
                            } else if (ev.data?.type === 'privasys:social-error') {
                                cleanup();
                                popup.close();
                                reject(new Error(ev.data.error || 'Social authentication failed'));
                            }
                        };

                        window.addEventListener('message', onMessage);

                        // Detect if user closes the popup manually.
                        const pollClosed = setInterval(() => {
                            if (popup.closed) {
                                cleanup();
                                reject(new Error('Authentication cancelled'));
                            }
                        }, 500);
                    });
                };

                activeUI = new AuthUI({
                    ...config,
                    apiBase: idpBase,
                    sessionId: oidcSessionId,
                    fido2Base: `${idpBase}/fido2`,
                    pushToken,
                    deviceTrusted,
                    socialProviders,
                    onSocialAuth,
                    requestedAttributes,
                });

                const uiResult: SignInResult = await activeUI.signIn();

                // 5. Get the auth code:
                //    - Passkey: the IdP's FIDO2 handler already marked the session
                //      complete, so poll for it.
                //    - Wallet (relay): call /session/complete to bridge.
                //    - Social: the popup callback already marked it complete, so
                //      call /session/complete to get the code (it's idempotent).
                let code: string;
                if (uiResult.method === 'passkey') {
                    code = await pollSessionStatus(pollUrl);
                } else {
                    // Wallet: pass profile from relay. Social: auth code
                    // already exists with profile (the popup callback created it).
                    code = await completeSession(
                        idpBase,
                        oidcSessionId,
                        uiResult.attributes,
                    );
                }

                // 5. Exchange code for JWT tokens.
                const tokens = await exchangeCode(idpBase, code, clientId, codeVerifier);

                // 6. Store session with JWT access_token and refresh_token.
                const rpId = config.rpId || config.appName;
                const session: AuthSession = {
                    token: tokens.access_token,
                    rpId,
                    origin: config.apiBase,
                    authenticatedAt: Date.now(),
                    pushToken: uiResult.pushToken,
                    brokerUrl: config.brokerUrl || '',
                    refreshToken: tokens.refresh_token,
                    clientId,
                };
                sessions.store(session);
                if (session.pushToken && session.brokerUrl) {
                    if (uiResult.trustDevice || deviceTrusted) {
                        sessions.saveDeviceHint(session.pushToken, session.brokerUrl);
                    }
                }
                scheduleRenewal(session, parentOrigin);

                // 7. Send result to parent with the access_token.
                window.parent.postMessage(
                    {
                        type: 'privasys:result',
                        result: {
                            ...uiResult,
                            accessToken: tokens.access_token,
                        },
                    },
                    parentOrigin,
                );
            } catch (err) {
                const msg = err instanceof Error ? err.message : 'Authentication failed';
                if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                    window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
                } else {
                    window.parent.postMessage({ type: 'privasys:error', error: msg }, parentOrigin);
                }
            } finally {
                activeUI = null;
            }
            return;
        }

        // Non-OIDC mode (original flow): opaque session token from enclave.
        const pushToken = sessions.findPushToken();
        const deviceTrusted = !!sessions.getDeviceHint();
        activeUI = new AuthUI({ ...config, pushToken, deviceTrusted });

        try {
            const result: SignInResult = await activeUI.signIn();

            const brokerUrl = config.brokerUrl || '';

            // Persist session in privasys.id localStorage
            const session: AuthSession = {
                token: result.sessionToken,
                rpId: config.rpId || config.appName,
                origin: config.apiBase,
                authenticatedAt: Date.now(),
                pushToken: result.pushToken,
                brokerUrl,
            };
            sessions.store(session);

            // Schedule automatic renewal before TTL expires
            if (session.pushToken && session.brokerUrl) {
                if (result.trustDevice || deviceTrusted) {
                    sessions.saveDeviceHint(session.pushToken, session.brokerUrl);
                }
                scheduleRenewal(session, parentOrigin);
            }

            window.parent.postMessage(
                { type: 'privasys:result', result },
                parentOrigin,
            );
        } catch (err) {
            const msg = err instanceof Error ? err.message : 'Authentication failed';
            if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
            } else {
                window.parent.postMessage({ type: 'privasys:error', error: msg }, parentOrigin);
            }
        } finally {
            activeUI = null;
        }
    }

    if (data.type === 'privasys:check-session') {
        let session = sessions.get(data.rpId);

        // If the access token is expired but we have a refresh token,
        // renew immediately before returning so the parent gets a fresh token.
        if (session?.token && session?.refreshToken && session?.clientId && isTokenExpired(session.token)) {
            try {
                await renewSession(session, e.origin, false);
                session = sessions.get(data.rpId);
            } catch {
                // Renewal failed — clear and return null so parent triggers sign-in.
                sessions.remove(data.rpId);
                session = undefined;
            }
        }

        // Ensure renewal is running for active sessions
        if (session?.refreshToken && session?.clientId && !renewalTimers.has(session.rpId)) {
            scheduleRenewal(session, e.origin);
        }

        window.parent.postMessage(
            { type: 'privasys:session', session: session || null },
            e.origin,
        );
    }

    if (data.type === 'privasys:clear-session') {
        cancelRenewal(data.rpId);
        sessions.remove(data.rpId);
        sessions.clearDeviceHint();
        window.parent.postMessage(
            { type: 'privasys:session-cleared' },
            e.origin,
        );
    }
});

// Signal to parent that the iframe is ready to receive messages
window.parent.postMessage({ type: 'privasys:ready' }, '*');
