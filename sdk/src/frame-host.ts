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
import { SessionManager, SESSIONS_STORAGE_KEY } from './session';
import type { AuthSession } from './types';
import { PrivasysSession, type EncAuthEnvelope } from './enclave-session';

const sessions = new SessionManager();

let activeUI: AuthUI | null = null;

// ── Sealed session-relay state (iframe-scoped) ───────────────────────────
//
// When the parent opts into session-relay we generate the SDK ephemeral
// P-256 keypair *here* (the private key never leaves the iframe origin).
// After the wallet attests the enclave and returns {session_id, enc_pub}
// over the broker, we derive K, instantiate a PrivasysSession, and expose
// a `privasys:session:request` postMessage RPC so the parent can issue
// sealed requests without ever seeing K or the plaintext envelope.

interface PendingHandshake {
    appHost: string;
    /** rpId of the OIDC session this sealed handshake belongs to; used to
     *  look up the bearer token for EncAuth voucher fetches. */
    rpId: string;
    sdkKeyPair: CryptoKeyPair;
    sdkPubB64: string;
}

interface ActiveSession {
    appHost: string;
    sessionId: string;
    expiresAt: number;
    session: PrivasysSession;
}

let pendingHandshake: PendingHandshake | null = null;
let activeSession: ActiveSession | null = null;

/** Read a string claim out of a JWT without verification (the IdP signed it). */
function jwtClaim(token: string, claim: string): string | null {
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        const v = payload[claim];
        return typeof v === 'string' && v ? v : null;
    } catch {
        return null;
    }
}

/**
 * Build the EncAuth voucher fetcher for silent rebind / cold resume.
 * Reads the freshest bearer token for `rpId` from this origin's session
 * store at call time (renewal may have rotated it since install) and
 * fetches the wallet-signed envelope from the IdP. Returns null when
 * there is no session, no `sid` claim, or no stored voucher — the
 * caller then falls back to a wallet ceremony.
 */
function makeGetEncAuth(rpId: string, host: string): () => Promise<EncAuthEnvelope | null> {
    return async () => {
        const session = sessions.get(rpId);
        if (!session?.token) return null;
        const sid = jwtClaim(session.token, 'sid');
        if (!sid) return null;
        // Select the voucher for THIS enclave by host. The browser can't compute
        // app_id (it never attests), so host is the resume selector; the enclave
        // re-verifies the voucher's app_id at consumption. Multi-app sessions
        // hold one voucher per host on the same sid — without the selector the
        // IdP would return the most-recent (wrong) one.
        const url =
            `${globalThis.location.origin}/sessions/${encodeURIComponent(sid)}/encauth` +
            (host ? `?host=${encodeURIComponent(host)}` : '');
        const resp = await fetch(url, { headers: { Authorization: `Bearer ${session.token}` } });
        if (!resp.ok) return null;
        return (await resp.json()) as EncAuthEnvelope;
    };
}

async function generateSdkKeyPair(): Promise<{ keyPair: CryptoKeyPair; sdkPubB64: string }> {
    const keyPair = (await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false, // non-extractable: private key stays in this origin's WebCrypto store
        ['deriveBits'],
    )) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    if (raw.byteLength !== 65 || raw[0] !== 0x04) {
        throw new Error('frame-host: unexpected SEC1 encoding for SDK pubkey');
    }
    let s = '';
    for (let i = 0; i < raw.byteLength; i++) s += String.fromCharCode(raw[i]);
    const sdkPubB64 = btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { keyPair, sdkPubB64 };
}

// ── Session renewal (OIDC refresh_token) ────────────────────────────────
//
// Renewal coordination is client-side and cross-document. Several
// privasys.id iframes can be alive at once for the same session chain:
// the persistent renewal iframe, a sealed sign-in iframe kept mounted
// for session-relay, and one of each per additional tab. The IdP
// rotates refresh tokens with strict single-use semantics (the old
// token is deleted before the new one is issued), so exactly one
// document may run a refresh grant for a given (clientId, rpId) chain
// at a time. Every refresh-grant consumer in this file — the scheduled
// renewal, the inline check-session renewal, and audience-token
// minting — is serialised through the Web Locks API, which is
// origin-scoped across documents and tabs.
//
// Renewal is scheduled from the access token's `exp` claim (not a flat
// delay), retries transient failures with backoff, and never removes
// the session unless the refresh-token chain is provably dead.

/** Renew when the token has less than this long to live. */
const RENEW_MARGIN_MS = 90_000;
/** Random spread so N documents don't fire at the same instant. */
const RENEW_JITTER_MS = 15_000;
/** Backoff schedule for transient renewal failures (network, IdP 5xx). */
const RENEW_RETRY_MS = [5_000, 30_000, 120_000];
/** Backstop cadence; no-ops unless the token is inside the margin. */
const RENEW_HEARTBEAT_MS = 60_000;

const renewalTimers = new Map<string, ReturnType<typeof setTimeout>>();
const renewalRetryCount = new Map<string, number>();
/** rpIds this document renews, with the parent origin to notify. */
const renewalParents = new Map<string, string>();
/** Last access token seen per rpId; dedupes storage-event notifications. */
const lastSeenTokens = new Map<string, string>();

function cancelRenewal(rpId: string): void {
    const timer = renewalTimers.get(rpId);
    if (timer) {
        clearTimeout(timer);
        renewalTimers.delete(rpId);
    }
    renewalRetryCount.delete(rpId);
    renewalParents.delete(rpId);
}

/**
 * Serialise a refresh-token-grant user across all privasys.id documents
 * (iframes and tabs). Falls back to running unlocked when the Web Locks
 * API is unavailable — best effort, matching pre-lock behaviour.
 */
async function withRefreshLock<T>(rpId: string, clientId: string, fn: () => Promise<T>): Promise<T> {
    const locks = (navigator as Navigator & { locks?: LockManager }).locks;
    if (locks?.request) {
        return locks.request(`privasys-refresh:${clientId}:${rpId}`, fn) as Promise<T>;
    }
    return fn();
}

/** Epoch-ms `exp` of a JWT, or null when unreadable. */
function tokenExpMs(token: string): number | null {
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return typeof payload.exp === 'number' ? payload.exp * 1000 : null;
    } catch {
        return null;
    }
}

/** Check whether an access token's exp claim is within a safety margin. */
function isTokenExpired(token: string, marginMs = 30_000): boolean {
    const exp = tokenExpMs(token);
    if (exp === null) return false;
    return exp - marginMs < Date.now();
}

/** True when the token should be renewed now (inside the renewal margin). */
function needsRenewal(token: string): boolean {
    return isTokenExpired(token, RENEW_MARGIN_MS);
}

function scheduleRenewal(session: AuthSession, parentOrigin: string): void {
    cancelRenewal(session.rpId);

    if (!session.refreshToken || !session.clientId) return;

    renewalParents.set(session.rpId, parentOrigin);
    lastSeenTokens.set(session.rpId, session.token);

    // Schedule from the token's actual exp; a flat delay drifts apart
    // from the token lifetime whenever the iframe is (re)created after
    // sign-in. Unknown exp falls back to the historical 13 minutes.
    const exp = tokenExpMs(session.token);
    const base = exp === null ? 13 * 60 * 1000 : exp - Date.now() - RENEW_MARGIN_MS;
    const jitter = Math.floor(Math.random() * RENEW_JITTER_MS);
    const delay = Math.max(1_000, base + jitter);

    const timer = setTimeout(() => {
        renewalTimers.delete(session.rpId);
        void renewIfNeeded(session.rpId, parentOrigin);
    }, delay);

    renewalTimers.set(session.rpId, timer);
}

function scheduleRenewalRetry(rpId: string, parentOrigin: string): void {
    const attempt = renewalRetryCount.get(rpId) ?? 0;
    renewalRetryCount.set(rpId, attempt + 1);
    const delay = RENEW_RETRY_MS[Math.min(attempt, RENEW_RETRY_MS.length - 1)];
    const prev = renewalTimers.get(rpId);
    if (prev) clearTimeout(prev);
    const timer = setTimeout(() => {
        renewalTimers.delete(rpId);
        void renewIfNeeded(rpId, parentOrigin);
    }, delay);
    renewalTimers.set(rpId, timer);
}

/**
 * Renew the session for `rpId` if (and only if) its token is inside the
 * renewal margin, under the cross-document refresh lock. Re-reads the
 * session from localStorage after acquiring the lock so a renewal that
 * another document just completed turns this call into a no-op instead
 * of a double-spend of the rotated refresh token.
 *
 * Returns the freshest session (renewed or not), or undefined when the
 * chain is dead and the session has been removed.
 */
async function renewIfNeeded(
    rpId: string,
    parentOrigin: string,
    notify = true,
): Promise<AuthSession | undefined> {
    const current = sessions.get(rpId);
    if (!current?.refreshToken || !current?.clientId) return current;
    if (!needsRenewal(current.token)) {
        // Not due yet (timer fired early relative to a token another
        // document already rotated) — just re-arm from the fresh exp.
        if (!renewalTimers.has(rpId)) scheduleRenewal(current, parentOrigin);
        return current;
    }

    return withRefreshLock(rpId, current.clientId, async () => {
        // Re-read under the lock: another document may have renewed
        // while we waited.
        const fresh = sessions.get(rpId);
        if (!fresh?.refreshToken || !fresh?.clientId) return fresh;
        if (!needsRenewal(fresh.token)) {
            renewalRetryCount.delete(rpId);
            scheduleRenewal(fresh, parentOrigin);
            return fresh;
        }
        return renewSessionLocked(fresh, parentOrigin, notify);
    });
}

/**
 * Run one refresh_token grant. Must be called with the refresh lock
 * held. Failure handling is deliberately non-destructive:
 *  - invalid_grant with a newer token in storage → adopt it (a
 *    non-locking client rotated underneath us during rollout);
 *  - invalid_grant with no newer token → the chain is dead (revoked
 *    sid, expired refresh token) → remove + session-expired;
 *  - anything else (network, 5xx) → keep the session, retry with
 *    backoff.
 */
async function renewSessionLocked(
    session: AuthSession,
    parentOrigin: string,
    notify: boolean,
): Promise<AuthSession | undefined> {
    const idpBase = globalThis.location.origin;
    const usedRefreshToken = session.refreshToken!;

    let resp: Response;
    try {
        resp = await fetch(`${idpBase}/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: usedRefreshToken,
                client_id: session.clientId!,
            }),
        });
    } catch (err) {
        console.warn('[frame-host] renewal fetch failed, will retry:', err);
        scheduleRenewalRetry(session.rpId, parentOrigin);
        return session;
    }

    if (resp.ok) {
        const tokens = await resp.json();
        const updated: AuthSession = {
            ...session,
            token: tokens.access_token,
            refreshToken: tokens.refresh_token,
            authenticatedAt: Date.now(),
        };
        sessions.store(updated);
        renewalRetryCount.delete(session.rpId);
        scheduleRenewal(updated, parentOrigin);

        // Notify parent — skipped during check-session inline renewal to
        // avoid a double-message race (session-renewed before session
        // response).
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
        return updated;
    }

    const body = await resp.json().catch(() => ({ error: resp.statusText }));
    const errCode = typeof body.error === 'string' ? body.error : '';

    if (resp.status === 400 && errCode === 'invalid_grant') {
        // The token we used is gone server-side. If storage now holds a
        // different refresh token, another (non-locking) party rotated
        // it — adopt theirs rather than killing the session.
        const stored = sessions.get(session.rpId);
        if (stored?.refreshToken && stored.refreshToken !== usedRefreshToken) {
            renewalRetryCount.delete(session.rpId);
            scheduleRenewal(stored, parentOrigin);
            return stored;
        }
        console.warn('[frame-host] refresh-token chain dead, expiring session:', body);
        cancelRenewal(session.rpId);
        sessions.remove(session.rpId);
        // During check-session inline renewal (notify=false) the caller
        // reports the dead session as `session: null` itself; posting
        // session-expired too would race the parent's response handler.
        if (notify) {
            window.parent.postMessage(
                { type: 'privasys:session-expired', rpId: session.rpId },
                parentOrigin,
            );
        }
        return undefined;
    }

    // 5xx / unexpected 4xx: transient until proven otherwise.
    console.warn(`[frame-host] renewal failed (${resp.status}), will retry:`, body);
    scheduleRenewalRetry(session.rpId, parentOrigin);
    return session;
}

// Cross-document propagation: when another iframe/tab renews a session
// we track, re-arm our timer from the fresh exp and forward the new
// access token to our parent so its in-memory copy doesn't go stale.
// (`storage` fires in every same-origin document except the writer.)
window.addEventListener('storage', (ev) => {
    if (ev.key !== SESSIONS_STORAGE_KEY) return;
    for (const [rpId, parentOrigin] of renewalParents) {
        const current = sessions.get(rpId);
        if (!current?.refreshToken || !current?.clientId) continue;
        if (lastSeenTokens.get(rpId) === current.token) continue;
        lastSeenTokens.set(rpId, current.token);
        scheduleRenewal(current, parentOrigin);
        window.parent.postMessage(
            {
                type: 'privasys:session-renewed',
                rpId,
                accessToken: current.token,
            },
            parentOrigin,
        );
    }
});

// Backstop heartbeat: one-shot timers can fire arbitrarily late in
// throttled/suspended documents. This interval (clamped to ≥1/min by
// the browser anyway) renews any tracked session that slipped inside
// the margin; the lock + in-lock re-read make overlapping heartbeats
// across documents harmless no-ops.
setInterval(() => {
    for (const [rpId, parentOrigin] of renewalParents) {
        const current = sessions.get(rpId);
        if (!current?.refreshToken || !current?.clientId) continue;
        if (needsRenewal(current.token)) void renewIfNeeded(rpId, parentOrigin);
    }
}, RENEW_HEARTBEAT_MS);

// ── OIDC PKCE helpers ───────────────────────────────────────────────────

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

// ---------------------------------------------------------------------------
// Post-passkey profile verification
// ---------------------------------------------------------------------------

/**
 * Show an inline UI asking the user to verify their identity via a social
 * provider (Google, GitHub, etc.) after passkey authentication. The social
 * callback on the IdP patches the verified email/name onto the existing
 * auth code so the final JWT carries those claims.
 */
function showProfileVerification(
    idpBase: string,
    sessionId: string,
    socialProviders: string[],
): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        // Build a simple inline overlay inside the iframe.
        const overlay = document.createElement('div');
        overlay.style.cssText =
            'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;' +
            'background:rgba(0,0,0,.45);z-index:10000;font-family:system-ui,sans-serif;';

        const card = document.createElement('div');
        card.style.cssText =
            'background:#fff;border-radius:12px;padding:32px 28px;max-width:380px;width:90%;' +
            'box-shadow:0 8px 32px rgba(0,0,0,.18);text-align:center;';

        const heading = document.createElement('h2');
        heading.textContent = 'Verify your identity';
        heading.style.cssText = 'margin:0 0 8px;font-size:18px;color:#1a1a2e;';

        const subtitle = document.createElement('p');
        subtitle.textContent =
            'To complete your account, sign in with one of these providers to verify your email.';
        subtitle.style.cssText = 'margin:0 0 20px;font-size:14px;color:#666;line-height:1.4;';

        card.appendChild(heading);
        card.appendChild(subtitle);

        const providerNames: Record<string, string> = {
            github: 'GitHub', google: 'Google',
            microsoft: 'Microsoft', linkedin: 'LinkedIn',
        };

        const openSocialPopup = (provider: string) => {
            const w = 500, h = 650;
            const left = window.screenX + (window.innerWidth - w) / 2;
            const top = window.screenY + (window.innerHeight - h) / 2;
            const popupUrl =
                `${idpBase}/auth/social?provider=${encodeURIComponent(provider)}` +
                `&session_id=${encodeURIComponent(sessionId)}`;
            const popup = window.open(
                popupUrl, 'privasys-social',
                `width=${w},height=${h},left=${left},top=${top}`,
            );

            if (!popup) {
                reject(new Error('Popup blocked — please allow popups for this site'));
                return;
            }

            const cleanup = () => {
                window.removeEventListener('message', onMsg);
                clearInterval(pollClosed);
                overlay.remove();
            };

            const onMsg = (ev: MessageEvent) => {
                if (ev.source !== popup) return;
                if (ev.data?.type === 'privasys:social-complete') {
                    cleanup(); popup.close(); resolve();
                } else if (ev.data?.type === 'privasys:social-error') {
                    cleanup(); popup.close();
                    reject(new Error(ev.data.error || 'Social verification failed'));
                }
            };
            window.addEventListener('message', onMsg);

            const pollClosed = setInterval(() => {
                if (popup.closed) {
                    cleanup();
                    reject(new Error('Verification cancelled'));
                }
            }, 500);
        };

        for (const provider of socialProviders) {
            const btn = document.createElement('button');
            btn.textContent = providerNames[provider] ?? provider;
            btn.style.cssText =
                'display:block;width:100%;padding:12px 16px;margin:8px 0;border:1px solid #ddd;' +
                'border-radius:8px;background:#fff;font-size:14px;cursor:pointer;' +
                'transition:background .15s;';
            btn.onmouseenter = () => { btn.style.background = '#f5f5f5'; };
            btn.onmouseleave = () => { btn.style.background = '#fff'; };
            btn.onclick = () => openSocialPopup(provider);
            card.appendChild(btn);
        }

        overlay.appendChild(card);
        document.body.appendChild(overlay);
    });
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
        const config: AuthUIConfig & {
            clientId?: string;
            scope?: string | string[];
            sessionRelay?: { appHost: string; extraAppHosts?: string[] };
        } = data.config;
        const parentOrigin = e.origin;

        // Tear down any previous UI / session-relay handshake.
        if (activeUI) {
            activeUI.destroy();
            activeUI = null;
        }
        pendingHandshake = null;

        // If the parent opted into session-relay, generate the SDK keypair
        // up-front and hand the public half to the AuthUI so the QR / push
        // request asks the wallet to bootstrap a sealed session against the
        // enclave during the FIDO2 ceremony. The private key never leaves
        // this iframe.
        let sessionRelayUI: AuthUIConfig['sessionRelay'] | undefined;
        if (config.sessionRelay?.appHost) {
            const { keyPair, sdkPubB64 } = await generateSdkKeyPair();
            pendingHandshake = {
                appHost: config.sessionRelay.appHost,
                rpId: config.rpId || config.appName,
                sdkKeyPair: keyPair,
                sdkPubB64,
            };
            sessionRelayUI = {
                sdkPub: sdkPubB64,
                appHost: config.sessionRelay.appHost,
                ...(config.sessionRelay.extraAppHosts?.length
                    ? { extraAppHosts: config.sessionRelay.extraAppHosts }
                    : {}),
            };
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
                    sessionRelay: sessionRelayUI,
                });

                const uiResult: SignInResult = await activeUI.signIn();

                // 5. Get the auth code:
                //    - Passkey: the IdP's FIDO2 handler already marked the session
                //      complete, so poll for it. If the relying party requested
                //      profile attributes (email/name), open a social login to
                //      source them — the social callback patches them onto the
                //      existing auth code.
                //    - Wallet (relay): call /session/complete to bridge.
                //    - Social: the popup callback already marked it complete, so
                //      call /session/complete to get the code (it's idempotent).
                let code: string;
                if (uiResult.method === 'passkey') {
                    // Check if the relying party needs profile attributes that
                    // passkey auth alone cannot provide (email, name).
                    const needsProfile = requestedAttributes?.some(
                        (a: string) => a === 'email' || a === 'name',
                    );
                    if (needsProfile) {
                        // Passkey alone cannot supply verified email/name —
                        // we MUST route the user through an external IdP
                        // before issuing the auth code. If the IdP is not
                        // configured with any social provider, fail loudly
                        // instead of silently completing with a profile-less
                        // user (regression observed in v0.2.1 where dropping
                        // provider env vars caused new passkey users to be
                        // created with no email/name and no way to recover).
                        if (socialProviders.length === 0) {
                            throw new Error(
                                'Profile verification required (email/name) ' +
                                'but the IdP has no external identity ' +
                                'providers configured. Contact support.',
                            );
                        }
                        // Show an inline profile-verification UI and open a
                        // social popup so the user's verified email/name gets
                        // attached to the auth code before token exchange.
                        await showProfileVerification(
                            idpBase, oidcSessionId, socialProviders,
                        );
                    }
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

                // Install the sealed session so the parent's `frame.session()`
                // RPC works once the auth result lands.
                if (uiResult.sessionRelay) {
                    await installSessionRelay(uiResult.sessionRelay, parentOrigin);
                }

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
        activeUI = new AuthUI({ ...config, pushToken, deviceTrusted, sessionRelay: sessionRelayUI });

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

            // Legacy opaque-token sessions have no refresh token; there is
            // no silent-renewal path for them (the old scheduleRenewal call
            // here was a no-op). Only persist the device hint.
            if (session.pushToken && session.brokerUrl) {
                if (result.trustDevice || deviceTrusted) {
                    sessions.saveDeviceHint(session.pushToken, session.brokerUrl);
                }
            }

            if (result.sessionRelay) {
                await installSessionRelay(result.sessionRelay, parentOrigin);
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

        // If the access token is inside the renewal margin and we have a
        // refresh token, renew inline (under the cross-document lock)
        // before returning so the parent gets a fresh token. A dead
        // chain comes back as undefined → parent triggers sign-in.
        if (session?.token && session?.refreshToken && session?.clientId && needsRenewal(session.token)) {
            session = await renewIfNeeded(data.rpId, e.origin, false);
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

    // Mint a per-audience access token without rotating the user's primary
    // session. Used by chat to call as.privasys.org/verify-quote with an
    // `aud=attestation-server` JWT. Implementation: refresh_token grant
    // with an explicit `scope` form param (RFC 6749 §6 + audience extension).
    // The new refresh token returned by the IdP keeps the original scope,
    // so subsequent renewals continue to mint platform-audience tokens.
    if (data.type === 'privasys:get-token-for-audience') {
        const id = data.id;
        const reply = (payload: Record<string, unknown>) =>
            window.parent.postMessage(
                { type: 'privasys:token-for-audience:response', id, ...payload },
                e.origin,
            );
        const session = sessions.get(data.rpId);
        if (!session?.refreshToken || !session?.clientId) {
            reply({ error: 'no refresh token in session' });
            return;
        }
        const audience = String(data.audience || '').trim();
        if (!audience) {
            reply({ error: 'audience required' });
            return;
        }
        try {
            // Audience minting consumes (and rotates) the same single-use
            // refresh token as silent renewal, so it runs under the same
            // cross-document lock, re-reading the freshest token inside.
            const tok = await withRefreshLock(data.rpId, session.clientId, async () => {
                const fresh = sessions.get(data.rpId);
                if (!fresh?.refreshToken || !fresh?.clientId) {
                    throw new Error('no refresh token in session');
                }
                const idpBase = globalThis.location.origin;
                const resp = await fetch(`${idpBase}/token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        grant_type: 'refresh_token',
                        refresh_token: fresh.refreshToken,
                        client_id: fresh.clientId,
                        scope: `audience:${audience} openid email profile offline_access`,
                    }),
                });
                if (!resp.ok) {
                    const body = await resp.json().catch(() => ({ error: resp.statusText }));
                    throw new Error(body.error_description || body.error || `mint failed: ${resp.status}`);
                }
                const minted = await resp.json();
                // The IdP rotated the refresh token. Persist the new one so
                // the next user-scope refresh uses a valid handle, but DO
                // NOT touch the access token — that one is audience-bound.
                sessions.store({ ...fresh, refreshToken: minted.refresh_token });
                return minted;
            });
            reply({ accessToken: tok.access_token, expiresIn: tok.expires_in });
        } catch (err) {
            reply({ error: (err as Error).message });
        }
    }

    // Sealed session-relay RPC. The parent serialises the request as
    // {method, path, body?} and we relay it through PrivasysSession.request
    // (CBOR-sealed AES-256-GCM over fetch). Only the iframe holds K, so the
    // parent can never inspect or replay sealed traffic.
    if (data.type === 'privasys:session:request') {
        const id = data.id;
        const reply = (payload: Record<string, unknown>) =>
            window.parent.postMessage({ type: 'privasys:session:response', id, ...payload }, e.origin);
        if (!activeSession) {
            reply({ error: 'no active session' });
            return;
        }
        // No pre-emptive expiry gate here: with the sliding enclave TTL an
        // active session never wall-clock-expires, and a forgotten one
        // comes back as an unsealed 401 that PrivasysSession.request()
        // resolves via EncAuth silent rebind.
        try {
            const method = String(data.method || 'GET').toUpperCase();
            const path = String(data.path || '/');
            const body = data.body as unknown;
            const init = (data.init as RequestInit | undefined) ?? undefined;
            const resp = await activeSession.session.request(method, path, body, init);
            const headers: Record<string, string> = {};
            resp.headers.forEach((v, k) => { headers[k] = v; });
            reply({
                status: resp.status,
                headers,
                body: resp.body,
                sealed: resp.sealed,
            });
        } catch (err) {
            reply({ error: err instanceof Error ? err.message : String(err) });
        }
    }

    // Cold resume: re-establish a sealed session purely from the stored
    // EncAuth voucher — no wallet ceremony, no push. Used by the parent
    // after a page reload, when the OIDC session restored via SSO but
    // the iframe-resident sealed session (deliberately never persisted)
    // is gone. Idempotent: an already-active session for the same
    // appHost is returned as-is.
    if (data.type === 'privasys:session:resume') {
        const id = data.id;
        const reply = (payload: Record<string, unknown>) =>
            window.parent.postMessage({ type: 'privasys:session:resume:response', id, ...payload }, e.origin);
        const appHost = String(data.appHost || '');
        const rpId = String(data.rpId || '');
        if (!appHost || !rpId) {
            reply({ error: 'appHost and rpId required' });
            return;
        }
        if (activeSession && activeSession.appHost === appHost) {
            reply({ sessionId: activeSession.sessionId, appHost, expiresAt: activeSession.expiresAt });
            return;
        }
        const getEncAuth = makeGetEncAuth(rpId, appHost);
        const result = await PrivasysSession.resume({ host: appHost, getEncAuth });
        if ('error' in result) {
            // 'no-voucher'    → user never completed a sealed sign-in here
            // 'rejected'      → enclave identity/measurement changed; a
            //                   wallet ceremony is required
            // 'unavailable'   → transport failure, worth retrying
            reply({ error: result.error });
            return;
        }
        activeSession = {
            appHost,
            sessionId: result.session.sessionId,
            expiresAt: 0,
            session: result.session,
        };
        reply({ sessionId: result.session.sessionId, appHost, expiresAt: 0 });
        return;
    }

    // Sealed streaming RPC. The parent posts a single
    // `privasys:session:stream-request`; the iframe replies with one
    // `privasys:session:stream-start` (carrying status + headers) followed
    // by zero or more `privasys:session:stream-chunk` messages and finally
    // `privasys:session:stream-end` (or `privasys:session:stream-error`).
    if (data.type === 'privasys:session:stream-request') {
        const id = data.id;
        const post = (type: string, payload: Record<string, unknown> = {}) =>
            window.parent.postMessage({ type, id, ...payload }, e.origin);
        if (!activeSession) {
            post('privasys:session:stream-error', { error: 'no active session' });
            return;
        }
        try {
            const method = String(data.method || 'POST').toUpperCase();
            const path = String(data.path || '/');
            const body = data.body as unknown;
            const init = (data.init as RequestInit | undefined) ?? undefined;
            const resp = await activeSession.session.stream(method, path, body, init);
            const headers: Record<string, string> = {};
            resp.headers.forEach((v, k) => { headers[k] = v; });
            post('privasys:session:stream-start', { status: resp.status, headers, sealed: resp.sealed });
            const reader = resp.body.getReader();
            try {
                for (;;) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    if (value && value.byteLength > 0) {
                        post('privasys:session:stream-chunk', { chunk: value });
                    }
                }
                post('privasys:session:stream-end');
            } catch (err) {
                post('privasys:session:stream-error', {
                    error: err instanceof Error ? err.message : String(err),
                });
            }
        } catch (err) {
            post('privasys:session:stream-error', {
                error: err instanceof Error ? err.message : String(err),
            });
        }
    }
});

/**
 * Normalise an enclave-supplied expiry to epoch ms. The wire contract
 * uses epoch seconds (crypto-contract §3); older Go enclaves sent epoch
 * ms. Values below 1e12 cannot be a sane epoch-ms after Sep 2001, so
 * they are treated as seconds.
 */
function normalizeEpochMs(v: number | undefined): number {
    if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) return 0;
    return v < 1e12 ? v * 1000 : v;
}

async function installSessionRelay(
    binding: { sessionId: string; encPub: string; expiresAt?: number },
    parentOrigin: string,
): Promise<void> {
    if (!pendingHandshake) {
        console.warn('[frame-host] sessionRelay returned without pending handshake — ignoring');
        return;
    }
    const { sdkKeyPair, appHost, rpId } = pendingHandshake;
    pendingHandshake = null;
    const expiresAtMs = normalizeEpochMs(binding.expiresAt);
    try {
        const session = await PrivasysSession.fromHandshake({
            host: appHost,
            sessionId: binding.sessionId,
            sdkPrivateKey: sdkKeyPair.privateKey,
            encPub: binding.encPub,
            // Silent rebind: when the enclave forgets this session (idle
            // TTL, restart with the same identity) the next request's
            // unsealed 401 triggers a voucher-based re-bootstrap with no
            // wallet involvement.
            getEncAuth: makeGetEncAuth(rpId, appHost),
        });
        activeSession = {
            appHost,
            sessionId: binding.sessionId,
            expiresAt: expiresAtMs,
            session,
        };
        window.parent.postMessage(
            {
                type: 'privasys:session:ready',
                sessionId: binding.sessionId,
                appHost,
                expiresAt: expiresAtMs,
            },
            parentOrigin,
        );
    } catch (err) {
        console.error('[frame-host] failed to derive sealed session:', err);
        window.parent.postMessage(
            {
                type: 'privasys:session:error',
                error: err instanceof Error ? err.message : String(err),
            },
            parentOrigin,
        );
    }
}

// Signal to parent that the iframe is ready to receive messages
window.parent.postMessage({ type: 'privasys:ready' }, '*');
