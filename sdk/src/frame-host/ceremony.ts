// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The OIDC sign-in: authorize, the gate, step-up, social popups, the
 * code exchange, and storing the session.
 */

import { PrivasysSession } from '../enclave-session';
import { FRAME_SIZE_MESSAGE } from '../frame-size';
import { sanitiseChoice, type GateState } from '../gate-headless';
import { sanitiseDisplayNames, sanitiseIcons, sanitiseOwn, sanitiseProviders, selectProviders, type OwnRegistration } from '../providers';
import type { SessionKey } from '../session';
import { sanitiseTheme } from '../theme';
import type { AuthSession } from '../types';
import { AuthUI, type AuthUIConfig, type SignInResult } from '../ui';
import { DEVICE_POPUP_URL, deviceLabels, shown, askDevicePopup } from './device-popup';
import { type DeviceRequest, deviceGate, lookupDeviceRequest, operationGate, sanitiseOperation, waitAuthenticated } from './idp-approvals';
import { sessions } from './page-scope';
import { scheduleRenewal } from './renewal';
import type { MessageContext } from './router';
import { sanitisePitch, sanitiseApp, sanitiseLinkNonce, sanitiseDeviceUserCode, sanitiseAudience, sanitiseMethods, sanitisePresentation, sanitiseSpend } from './sanitise';
import { adoptSession, makeGetEncAuth, SAME_DEVICE_VOUCHER_WINDOW_MS, CEREMONY_VOUCHER_WINDOW_MS, resumeVoucherSession, requestVoucherPush, generateSdkKeyPair, installSessionRelay, sealed } from './sealed-bridge';
import { b64urlJson, tokenSaysWallet, isTokenExpired } from './tokens';

let activeUI: AuthUI | null = null;

/**
 * How long the step-up approve gate waits for the holder to act on the
 * pushed attribute approval before falling back to the full ceremony.
 * Deliberately well inside the authorize session's 5-minute window so the
 * fallback ceremony still has time to complete on the same session.
 */
export const STEP_UP_APPROVAL_WINDOW_MS = 90_000;

// ── OIDC PKCE helpers ───────────────────────────────────────────────────

export async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
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
export async function pollSessionStatus(pollUrl: string, timeoutMs = 120_000): Promise<string> {
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
export async function completeSession(
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
export async function exchangeCode(
    idpBase: string,
    code: string,
    clientId: string,
    codeVerifier: string,
): Promise<{ access_token: string; id_token?: string; refresh_token?: string; expires_in: number }> {
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

// contentHeightReporter posts the rendered UI's height to the parent page,
// at most once per animation frame, so an inline embed can size its iframe
// to the content (frame-size.ts).
export function contentHeightReporter(parentOrigin: string): (px: number) => void {
    let pending: number | null = null;
    return (px: number): void => {
        pending = px;
        const flush = (): void => {
            if (pending === null) return;
            const height = pending;
            pending = null;
            window.parent.postMessage({ type: FRAME_SIZE_MESSAGE, height }, parentOrigin);
        };
        if (typeof requestAnimationFrame === 'function') requestAnimationFrame(flush);
        else flush();
    };
}

// How a device sign-in or an operation approval can end without approval,
// with the gate staying on that outcome (AuthUI rejects with these codes).
export const GATE_OUTCOMES = ['declined', 'decline-failed', 'approval-failed'] as const;
export const isGateOutcome = (code: string): code is typeof GATE_OUTCOMES[number] =>
    (GATE_OUTCOMES as readonly string[]).includes(code);
export const gateOutcomeResult = (code: string) =>
    ({ approved: false, outcome: code, sessionToken: '', method: 'wallet', sessionId: '' });

/**
 * The page asks for the gate: a sign-in, a link, or one of the identity
 * provider's approvals. Runs it in this frame and posts how it ended.
 */
export async function onInit({ e, data, pageScope }: MessageContext): Promise<void> {
    const config: AuthUIConfig & {
        /** The page's API origin, recorded on the session. */
        apiBase?: string;
        clientId?: string;
        scope?: string | string[];
        sessionRelay?: { appHost: string; extraAppHosts?: string[] };
        spend?: { cap?: number };
        connect?: { mode?: string; reason?: string | null; added?: string[] };
        caps?: string[];
        billingGrant?: string;
        attributes?: readonly string[];
        /** Adopter theme and footer choice; sanitised below. */
        theme?: unknown;
        legal?: unknown;
        /** The audience of the first access token; sanitised below. */
        audience?: unknown;
        /** Adopter preference for the social providers; sanitised below. */
        providers?: unknown;
        /** The page draws its own gate; sanitised below. */
        headless?: unknown;
        /** Link a Privasys ID to a person signed in another way; sanitised below. */
        link?: unknown;
        /** Approve a sign-in another device started; sanitised below. */
        deviceRequest?: unknown;
        /** Approve an operation someone started; sanitised below. */
        operationApproval?: unknown;
    } = data.config;
    const parentOrigin = e.origin;
    // A link is a Privasys ID sign-in whose only result is an ID token
    // for the page's server: who the person is under this client, proven
    // for the page's own nonce. Nothing of the page's existing session is
    // read or replaced, and nothing but the wallet can answer it.
    if (config.link !== undefined && !sanitiseLinkNonce(config.link)) {
        window.parent.postMessage({ type: 'privasys:error', error: 'link needs a nonce of 16 to 256 URL-safe characters' }, parentOrigin);
        return;
    }
    const linkNonce = sanitiseLinkNonce(config.link);
    if (linkNonce) {
        config.methods = ['wallet'];
        config.scope = 'openid';
        delete config.sessionRelay;
        delete config.spend;
        delete config.connect;
        delete config.billingGrant;
        delete config.attributes;
        delete config.audience;
    }
    // Only the device and operation approvals below keep the gate open on
    // their outcome; a page cannot ask for it.
    delete config.finalScreen;
    delete config.decline;
    // A device request: the ceremony runs on the request the other device
    // created, for the app that asked, so the holder sees that app's
    // consent and the device gets what it asked for. Only the identity
    // provider's own pages may ask for this: the code is the capability,
    // and a foreign page must not be able to walk a visitor through
    // approving someone else's device.
    let device: DeviceRequest | null = null;
    if (config.deviceRequest !== undefined) {
        const userCode = sanitiseDeviceUserCode(config.deviceRequest);
        if (!userCode || linkNonce || parentOrigin !== globalThis.location.origin) {
            window.parent.postMessage({ type: 'privasys:error', error: 'a device request cannot be approved from this page' }, parentOrigin);
            return;
        }
        try {
            device = await lookupDeviceRequest(globalThis.location.origin, userCode);
        } catch (err) {
            window.parent.postMessage({ type: 'privasys:error', error: err instanceof Error ? err.message : 'This code is invalid or has expired' }, parentOrigin);
            return;
        }
        config.methods = ['wallet'];
        Object.assign(config, deviceGate(userCode));
        config.clientId = device.clientId;
        config.appName = device.appName;
        config.rpId = device.rpId;
        if (device.brokerUrl) config.brokerUrl = device.brokerUrl;
        delete config.sessionRelay;
        delete config.spend;
        delete config.connect;
        delete config.billingGrant;
        delete config.attributes;
        delete config.audience;
    }
    // Every sign-in is for a client; only an operation approval, which
    // signs nobody in, has none.
    if (config.operationApproval === undefined && (typeof config.clientId !== 'string' || !config.clientId)) {
        window.parent.postMessage({ type: 'privasys:error', error: 'clientId is required' }, parentOrigin);
        return;
    }
    // A page gets its own platform's tokens and never another platform's.
    // Without the platform list there is no telling which is which, so
    // there is no sign-in.
    if (!pageScope) {
        window.parent.postMessage({ type: 'privasys:error', error: 'Sign-in is unavailable right now. Try again in a moment.' }, parentOrigin);
        return;
    }
    if (!device && !linkNonce) {
        const asked = sanitiseAudience(config.audience);
        if (asked && pageScope.platforms.includes(asked) && asked !== pageScope.platform) {
            window.parent.postMessage({ type: 'privasys:error', error: `audience ${asked} is not for a page on this platform` }, parentOrigin);
            return;
        }
        if (!asked && pageScope.platform !== pageScope.defaultPlatform) config.audience = pageScope.platform;
    }
    // The inline frame reports its content height so the embedding page
    // can size the iframe to it (frame-size.ts); throttled to a frame.
    const onContentHeight = contentHeightReporter(parentOrigin);

    // Wallet handoff via the parent page (mobile): only when the frame
    // client declared it handles `privasys:navigate` — older bundled
    // clients ignore unknown messages and the tap would go dead.
    const parentCaps = Array.isArray(config.caps) ? config.caps : [];
    const onNavigate = parentCaps.includes('parent-navigate')
        ? (url: string): void => {
            window.parent.postMessage({ type: 'privasys:navigate', url }, parentOrigin);
        }
        : undefined;
    // Headless: the page renders the gate itself from the options this
    // frame reports, and follows the flow through state reports. Only
    // a client that declared the capability gets the messages.
    const headless = config.headless === true && parentCaps.includes('headless');
    const onGateState = headless
        ? (s: GateState): void => {
            window.parent.postMessage({ type: 'privasys:gate:state', ...s }, parentOrigin);
        }
        : undefined;

    // Tear down any previous UI / session-relay handshake.
    if (activeUI) {
        activeUI.destroy();
        activeUI = null;
    }
    sealed.pending = null;

    // Adopter-supplied UI config, strictly sanitised (rendered in this
    // trusted origin). Used by every AuthUI constructed below.
    const presentation = sanitisePresentation(config.presentation);
    const pitch = sanitisePitch(config.pitch);
    const app = sanitiseApp(config.app);
    const theme = sanitiseTheme(config.theme);
    const legal = config.legal === false ? false : undefined;
    // The adopter's explicit choice of methods; when absent, the
    // OIDC path below additionally filters methods by ATTRIBUTE
    // capability (a method that cannot deliver what the app marked
    // as essential is hidden). Signing in without the wallet is a
    // supported, deliberately degraded mode (no attestation
    // verification) — never blanket-blocked.
    const methods = sanitiseMethods(config.methods);
    // The adopter's preferred external identity providers, applied to
    // the list the IdP publishes once it has been fetched below.
    const providers = sanitiseProviders(config.providers);

    // An operation someone started elsewhere, to approve. Only the
    // identity provider's own pages may run it: the request is the
    // capability, and a foreign page must not walk a visitor through
    // approving someone else's operation.
    if (config.operationApproval !== undefined) {
        const operation = sanitiseOperation(config.operationApproval);
        if (!operation || linkNonce || device || parentOrigin !== globalThis.location.origin) {
            window.parent.postMessage({ type: 'privasys:error', error: 'this approval cannot be shown on this page' }, parentOrigin);
            return;
        }
        const operationUI = new AuthUI({
            onContentHeight,
            appName: config.appName,
            rpId: config.rpId || config.appName,
            presentation,
            app,
            pitch,
            theme,
            legal,
            onNavigate,
            ...operationGate(operation, parentOrigin),
        });
        activeUI = operationUI;
        try {
            await operationUI.signIn();
            window.parent.postMessage(
                { type: 'privasys:result', result: { approved: true, sessionToken: '', method: 'wallet', sessionId: '' } },
                parentOrigin,
            );
        } catch (err) {
            const msg = err instanceof Error ? err.message : '';
            if (isGateOutcome(msg)) {
                // The gate shows how it ended and stays on it.
                window.parent.postMessage({ type: 'privasys:result', result: gateOutcomeResult(msg) }, parentOrigin);
            } else if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
            } else {
                window.parent.postMessage({ type: 'privasys:error', error: msg || 'The approval was not completed' }, parentOrigin);
            }
        } finally {
            if (activeUI === operationUI) activeUI = null;
        }
        return;
    }
    // The session this sign-in is for.
    const rpId = config.rpId || config.appName;
    const initKey: SessionKey = { platform: pageScope.platform, rpId, clientId: config.clientId! };
    // Connect-mode approve: an existing wallet session whose sealed
    // voucher the enclave refused (measurement change) or that has no
    // voucher for this app yet. One-tap wallet push re-verification,
    // rendered by AuthUI. Falls through to the full ceremony when it
    // cannot complete (no wallet push, timeout, or the user chose
    // "Sign in another way").
    // It RE-USES the stored access token, so it must never serve a
    // widened attribute request: a widened set needs a freshly minted
    // token, which only the OIDC ceremony (and its step-up push path)
    // can produce.
    if (config.connect?.mode === 'approve' && config.sessionRelay?.appHost
        && config.connect.reason !== 'attributes-widened') {
        const appHost = config.sessionRelay.appHost;
        const session = sessions.get(initKey);
        if (session?.token && session.pushToken && session.brokerUrl) {
            const appLabel = (config.appName || rpId)
                .replace(/[-_]/g, ' ')
                .replace(/\b\w/g, (c) => c.toUpperCase());
            const approveUI = new AuthUI({
                onContentHeight,
                appName: config.appName,
                rpId,
                presentation,
                app,
                pitch,
                theme,
                legal,
                headless,
                onGateState,
                approveFlow: {
                    appLabel,
                    reason: config.connect.reason ?? null,
                    run: async () => {
                        await requestVoucherPush({
                            key: initKey,
                            appName: config.appName,
                            appHost,
                        });
                        // Resume the sealed session from the fresh
                        // voucher and adopt it as this iframe's active
                        // sealed transport.
                        const getEncAuth = makeGetEncAuth(initKey, appHost);
                        const result = await PrivasysSession.resume({ host: appHost, getEncAuth });
                        if ('error' in result) {
                            throw new Error(result.reason
                                ? `${result.error}:${result.reason}`
                                : String(result.error));
                        }
                        adoptSession(appHost, result.session, 0, parentOrigin);
                    },
                },
            });
            activeUI = approveUI;
            try {
                await approveUI.signIn();
                // Sealed transport now lives in THIS iframe; hand the
                // parent the proxy handle and the result (existing token).
                window.parent.postMessage({
                    type: 'privasys:session:ready',
                    sessionId: sealed.active!.sessionId,
                    appHost,
                    expiresAt: 0,
                }, parentOrigin);
                const result: SignInResult = {
                    sessionToken: session.token,
                    method: 'wallet',
                    sessionId: sealed.active!.sessionId,
                    sessionRelay: {
                        sessionId: sealed.active!.sessionId,
                        encPub: '',
                        expiresAt: 0,
                    },
                };
                window.parent.postMessage({
                    type: 'privasys:result',
                    result: { ...result, accessToken: session.token },
                }, parentOrigin);
                activeUI = null;
                return;
            } catch (err) {
                activeUI = null;
                const msg = err instanceof Error ? err.message : '';
                if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                    window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
                    return;
                }
                // 'approve-fallback' or a hard failure — run the full
                // ceremony below in this same iframe.
            }
        }
        // No wallet-push-capable session → full ceremony below.
    }

    // If the parent opted into session-relay, generate the SDK keypair
    // up-front and hand the public half to the AuthUI so the QR / push
    // request asks the wallet to bootstrap a sealed session against the
    // enclave during the FIDO2 ceremony. The private key never leaves
    // this iframe.
    let sessionRelayUI: AuthUIConfig['sessionRelay'] | undefined;
    if (config.sessionRelay?.appHost) {
        const { keyPair, sdkPubB64 } = await generateSdkKeyPair();
        sealed.pending = {
            appHost: config.sessionRelay.appHost,
            key: initKey,
            sdkKeyPair: keyPair,
            sdkPubB64,
        };
        sessionRelayUI = {
            sdkPub: sdkPubB64,
            appHost: config.sessionRelay.appHost,
            ...(config.sessionRelay.extraAppHosts?.length
                ? { extraAppHosts: config.sessionRelay.extraAppHosts }
                : {}),
            // Spend consent rides the attested sign-in: the wallet knows
            // the app's attested identity (OID 3.6) only on this path.
            ...(config.spend ? { spend: sanitiseSpend(config.spend) } : {}),
        };
    }

    // IdP base URL (same origin as this iframe).
    const idpBase = globalThis.location.origin;
    const clientId = config.clientId!;

    // Create an OIDC session, authenticate, exchange the code for tokens.
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
        // The first token is the only one the identity provider can
        // put the person's profile in (it keeps none to renew from),
        // so a page that needs an audience token asks for it here
        // rather than minting one by refresh after the sign-in.
        const audience = sanitiseAudience(config.audience);
        authorizeUrl.searchParams.set('scope', audience ? `audience:${audience} ${scopeStr}` : scopeStr);
        authorizeUrl.searchParams.set('response_mode', 'json');
        // The page this frame is in, as the browser reported it: the
        // result of this sign-in goes to that page, so the identity
        // provider checks the client registered it.
        authorizeUrl.searchParams.set('parent_origin', parentOrigin);
        if (linkNonce) authorizeUrl.searchParams.set('nonce', linkNonce);
        // A billing grant redirects the cost of any paid attribute
        // disclosure from this app's owner to the user who issued the
        // grant, so the person requiring the proof pays for it. Opaque
        // here: its issuer owns its scope, ceiling and single use.
        if (config.billingGrant) {
            authorizeUrl.searchParams.set('billing_grant', config.billingGrant);
        }
        // Attributes named one by one, alongside the scope. A scope is a
        // coarse bundle and cannot reach a government-backed `_id` key at
        // all, so for those this is the request.
        if (config.attributes?.length) {
            authorizeUrl.searchParams.set('attributes', config.attributes.join(' '));
        }
        // An existing session identifies the holder without a scan, so
        // the IdP can push the DELTA of a widened request to their
        // wallet for one-tap approval instead of forcing a full QR
        // ceremony. The hint only says who to push to — it authorises
        // nothing; everything the holder grants still flows through
        // the wallet's own verification. Withheld for session-relay
        // apps: their sealed binding needs the full wallet ceremony,
        // so a push approval would ring the holder's phone for a flow
        // the browser cannot use.
        const priorSession = sessions.get(initKey);
        const stepUpEligible = !linkNonce && !device && !!(priorSession?.token
            && priorSession.clientId === clientId
            && !isTokenExpired(priorSession.token)
            && !config.sessionRelay?.appHost);
        if (stepUpEligible) {
            authorizeUrl.searchParams.set('session_hint', priorSession!.token);
        }
        const authorize = async () => {
            const authResp = await fetch(authorizeUrl.toString(), {
                headers: { Accept: 'application/json' },
            });
            if (!authResp.ok) {
                const body = await authResp.json().catch(() => ({ error: authResp.statusText }));
                const err = new Error(body.error_description || body.error || `Authorize failed: ${authResp.status}`);
                // Preserve the OAuth error code (e.g. `insufficient_credits`
                // on 402) so the parent can raise a typed error.
                (err as Error & { code?: string }).code = body.error;
                throw err;
            }
            return authResp.json();
        };
        // A device request already has its session at the identity
        // provider: the ceremony runs on that one, and no new request
        // is made.
        const authData = device
            ? {
                session_id: device.sessionId,
                poll_url: `${idpBase}/session/status?session_id=${encodeURIComponent(device.sessionId)}`,
                qr_payload: device.qrPayload,
                requested_attributes: device.requestedAttributes,
            }
            : await authorize();
        // The IdP keeps from the wallet any attribute the client's
        // registration does not allow. Signing in anyway would hand
        // the page a token without what it asked for, and the holder
        // an approval that showed less than the page expects, so the
        // sign-in fails and names the keys.
        const dropped: unknown = authData.dropped_attributes;
        if (Array.isArray(dropped) && dropped.length > 0) {
            const err = new Error(
                `This app may not ask for ${dropped.join(', ')}: its registration does not allow ${dropped.length === 1 ? 'it' : 'them'}`,
            );
            (err as Error & { code?: string; dropped?: string[] }).code = 'attributes_not_allowed';
            (err as Error & { code?: string; dropped?: string[] }).dropped = dropped.map(String);
            throw err;
        }
        const oidcSessionId: string = authData.session_id;
        const pollUrl: string = authData.poll_url;
        const requestedAttributes: string[] | undefined = authData.requested_attributes;

        // The authorize response embeds the full wallet payload —
        // including per-attribute assurance requirements and any
        // paid-disclosure vouchers minted for gov attributes — in
        // the universal-link's `p=` parameter. Decode it and thread
        // those fields into the AuthUI so the relay descriptor / push
        // carries them; without them the wallet treats every attr as
        // 'any' assurance and gov disclosure never happens on the
        // iframe path.
        let attributeRequirements: AuthUIConfig['attributeRequirements'];
        let disclosureVouchers: AuthUIConfig['disclosureVouchers'];
        try {
            const decoded = b64urlJson(new URL(authData.qr_payload).searchParams.get('p') ?? '');
            attributeRequirements = decoded?.attributeRequirements as AuthUIConfig['attributeRequirements'];
            disclosureVouchers = decoded?.disclosureVouchers as AuthUIConfig['disclosureVouchers'];
        } catch { /* no wallet payload to thread */ }

        // Step-up push: the IdP resolved the session hint, found this
        // request WIDER than what that session's holder last granted,
        // and pushed the delta to their wallet. Render the one-tap
        // approve gate and poll for completion. "Sign in another way"
        // or an unanswered push falls back to the full ceremony below
        // on the SAME authorize session — the unused push approval is
        // single-use, session-bound, and dies with the session.
        let code: string | null = null;
        let uiResult: SignInResult | null = null;
        const deviceTrusted = !!sessions.getDeviceHint();
        const stepUp = (stepUpEligible ? authData.step_up : null) as
            { pushed?: boolean; added?: string[] } | null | undefined;
        if (stepUp?.pushed) {
            const rpIdHint = config.rpId || config.appName;
            const appLabel = (config.appName || rpIdHint)
                .replace(/[-_]/g, ' ')
                .replace(/\b\w/g, (c) => c.toUpperCase());
            const approveUI = new AuthUI({
                onContentHeight,
                appName: config.appName,
                rpId: rpIdHint,
                presentation,
                app,
                pitch,
                theme,
                legal,
                headless,
                onGateState,
                approveFlow: {
                    appLabel,
                    reason: 'attributes-widened',
                    added: Array.isArray(stepUp.added) ? stepUp.added.map(String) : [],
                    run: async () => {
                        try {
                            code = await pollSessionStatus(pollUrl, STEP_UP_APPROVAL_WINDOW_MS);
                        } catch {
                            // Push not acted on in time (notifications
                            // off, phone out of reach) — fall back to
                            // the ceremony while the authorize session
                            // still has most of its window left.
                            throw new Error('approve-fallback');
                        }
                    },
                },
            });
            activeUI = approveUI;
            try {
                await approveUI.signIn();
            } catch (err) {
                const msg = err instanceof Error ? err.message : '';
                if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                    window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
                    return;
                }
                code = null; // 'approve-fallback' → full ceremony below
            } finally {
                if (activeUI === approveUI) activeUI = null;
            }
        }

        if (code === null) {
        // Attribute-capability filtering (only when the adopter did
        // not choose methods explicitly): hide methods that cannot
        // deliver what the app marked as ESSENTIAL.
        //   - Passkey provides no attributes at all — hidden when
        //     anything is essential (e.g. a share link requiring a
        //     verified email).
        //   - Social can deliver provider-verified standard
        //     attributes (email, name) but not gov-assurance
        //     disclosures — hidden only when an essential attribute
        //     needs 'gov' (wallet-only by design).
        //   - The wallet delivers everything.
        // With no essential attributes every method stays, including
        // the passkey-then-verify-profile flow further below.
        let effectiveMethods = methods;
        if (!effectiveMethods && attributeRequirements) {
            const essential = Object.values(attributeRequirements)
                .filter((r) => r?.essential);
            if (essential.some((r) => r.assurance === 'gov')) {
                effectiveMethods = ['wallet'];
            } else if (essential.length > 0) {
                effectiveMethods = ['wallet', 'social'];
            }
        }

        // 3. Fetch available social providers (skipped entirely when
        //    the effective methods exclude social sign-in).
        let socialProviders: string[] = [];
        let socialDisplayNames: Record<string, string> | undefined;
        let socialIcons: Record<string, string> | undefined;
        let socialOwn: OwnRegistration[] | undefined;
        if (!effectiveMethods || effectiveMethods.includes('social')) {
            try {
                // Named for the client, the identity provider lists only
                // the providers that client's users may sign in with.
                const provQuery = config.clientId ? `?client_id=${encodeURIComponent(config.clientId)}` : '';
                const provResp = await fetch(`${idpBase}/auth/social/providers${provQuery}`);
                if (provResp.ok) {
                    const provData = await provResp.json();
                    const published: string[] = provData.providers ?? [];
                    // A preference that matches nothing yields the published
                    // list (selectProviders): a gate with no button at all
                    // would strand the user. Say so, since this console is
                    // the frame's, not the adopter's.
                    socialProviders = selectProviders(published, providers);
                    socialDisplayNames = sanitiseDisplayNames(provData.display_names);
                    socialIcons = sanitiseIcons(provData.icons);
                    socialOwn = sanitiseOwn(provData.own);
                    if (providers && !providers.some((p) => published.includes(p))) {
                        console.warn(
                            '[privasys] none of the requested providers',
                            providers, 'is configured at the identity provider; offering', published,
                        );
                    }
                }
            } catch { /* social not available, that's fine */ }
        }

        // 4. Launch AuthUI with the OIDC session_id so QR/passkey link
        //    to the OIDC session; passkey calls go to the IdP's FIDO2 API.
        const pushToken = sessions.findPushToken();

        // Social auth handler: opens a popup to the IdP's social redirect,
        // then waits for the callback page to postMessage back.
        const openSocialPopup = (provider: string, own?: boolean, chooseAccount?: boolean): Promise<void> => {
            return new Promise<void>((resolve, reject) => {
                const w = 500, h = 650;
                const left = window.screenX + (window.innerWidth - w) / 2;
                const top = window.screenY + (window.innerHeight - h) / 2;
                // registration=own: the client's own registration, pressed as a button of its own.
                const popupUrl = `${idpBase}/auth/social?provider=${encodeURIComponent(provider)}&session_id=${encodeURIComponent(oidcSessionId)}${own ? '&registration=own' : ''}${chooseAccount ? '&account=choose' : ''}`;
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
        // Headless: a popup needs the click's activation, which the
        // page has and this frame does not, so the page opens it at
        // the address this frame names and reports how it ended.
        const popupViaParent = (provider: string, own?: boolean, chooseAccount?: boolean): Promise<void> => {
            return new Promise<void>((resolve, reject) => {
                const id = Math.random().toString(36).slice(2);
                const url = `${idpBase}/auth/social?provider=${encodeURIComponent(provider)}&session_id=${encodeURIComponent(oidcSessionId)}${own ? '&registration=own' : ''}${chooseAccount ? '&account=choose' : ''}`;
                const onMessage = (ev: MessageEvent) => {
                    if (ev.source !== window.parent || ev.origin !== parentOrigin) return;
                    if (ev.data?.type !== 'privasys:gate:popup-result' || ev.data.id !== id) return;
                    window.removeEventListener('message', onMessage);
                    if (ev.data.ok === true) resolve();
                    else reject(new Error(String(ev.data.error || 'Authentication cancelled')));
                };
                window.addEventListener('message', onMessage);
                window.parent.postMessage({ type: 'privasys:gate:popup', id, url }, parentOrigin);
            });
        };
        const onSocialAuth = headless ? popupViaParent : openSocialPopup;
        // The device popup: this frame opens it inside the click; a
        // headless page opens it for the frame, as it does a social one.
        const openDevicePopup = (): boolean | Promise<boolean> => {
            if (!headless) {
                const w = 420, h = 240;
                const left = window.screenX + (window.innerWidth - w) / 2;
                const top = window.screenY + (window.innerHeight - h) / 2;
                return !!window.open(DEVICE_POPUP_URL, 'privasys-device', `width=${w},height=${h},left=${left},top=${top}`);
            }
            return new Promise<boolean>((resolve) => {
                const id = Math.random().toString(36).slice(2);
                const onResult = (ev: MessageEvent) => {
                    if (ev.source !== window.parent || ev.origin !== parentOrigin) return;
                    if (ev.data?.type !== 'privasys:gate:popup-result' || ev.data.id !== id) return;
                    window.removeEventListener('message', onResult);
                    resolve(ev.data.ok === true);
                };
                window.addEventListener('message', onResult);
                window.parent.postMessage({ type: 'privasys:gate:popup', id, url: DEVICE_POPUP_URL }, parentOrigin);
            });
        };

        activeUI = new AuthUI({
            ...config,
            onContentHeight,
            sessionId: oidcSessionId,
            fido2Base: `${idpBase}/fido2`,
            pushToken,
            deviceTrusted,
            socialProviders,
            socialDisplayNames,
            socialIcons,
            socialOwn,
            onSocialAuth,
            devices: sessions.getDevices().map(shown),
            lookupDevice: async () => {
                const found = await askDevicePopup(openDevicePopup, { op: 'read' });
                for (const d of found) deviceLabels.set(d.pushToken, d.label);
                return found;
            },
            forgetDevice: async (token: string) => {
                sessions.forgetDevice(token);
                await askDevicePopup(openDevicePopup, { op: 'forget', pushToken: token });
            },
            rememberDevice: async (token: string, label?: string) => {
                await askDevicePopup(openDevicePopup, { op: 'store', pushToken: token, brokerUrl: config.brokerUrl || '', ...(label ? { label } : {}) });
            },
            // A passkey carries no name or email; the gate asks for
            // them through a provider when the client wants them.
            profileAfterPasskey: !!requestedAttributes?.some(
                (a: string) => a === 'email' || a === 'name',
            ),
            headless,
            onGateState,
            requestedAttributes,
            attributeRequirements,
            disclosureVouchers,
            sessionRelay: sessionRelayUI,
            // Same-device recovery: the AuthUI polls this while a
            // wallet flow is pending, so the ceremony completes
            // from IdP state when the broker relay died during the
            // app switch (page backgrounded → WS gone → the
            // wallet's relay message lands in the void).
            checkComplete: async () => {
                const r = await fetch(pollUrl, { cache: 'no-store' });
                if (!r.ok) return false;
                const d = await r.json().catch(() => null);
                return !!(d && d.authenticated);
            },
            // Sanitised copies override the raw postMessage values.
            presentation,
            app,
            pitch,
            theme,
            legal,
            methods: effectiveMethods,
            onNavigate,
            approveFlow: undefined,
        });

        if (headless) {
            window.parent.postMessage({ type: 'privasys:gate', options: activeUI.gateOptions() }, parentOrigin);
        }
        uiResult = await activeUI.signIn();

        // 5. Get the auth code:
        //    - Passkey: the IdP's FIDO2 handler already marked the session
        //      complete, so poll for it. If the relying party requested
        //      profile attributes (email/name), open a social login to
        //      source them — the social callback patches them onto the
        //      existing auth code.
        //    - Wallet (relay): call /session/complete to bridge.
        //    - Social: the popup callback already marked it complete, so
        //      call /session/complete to get the code (it's idempotent).
        if (device) {
            // The wallet answered over the relay: hand what it shared
            // to the identity provider, which completes the request.
            // A wallet that answered the identity provider directly
            // has completed it already.
            if (!uiResult.completedViaPoll) {
                await completeSession(idpBase, oidcSessionId, uiResult.attributes);
            }
            await waitAuthenticated(pollUrl);
            code = '';
        } else if (uiResult.method === 'passkey') {
            // A client that asked for the name or email had the gate
            // confirm them with a provider after the passkey
            // (profileAfterPasskey); the provider's callback added
            // them to this session.
            code = await pollSessionStatus(pollUrl);
        } else if (uiResult.completedViaPoll) {
            // Same-device wallet flow: the relay died during the app
            // switch, the ceremony completed via the IdP status
            // poll. The wallet already linked the FIDO2 assertion
            // and patched attributes onto the auth code server-side.
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
        } // end full ceremony (skipped when the step-up push completed)

        // 5. Exchange code for JWT tokens.
        // A device request is approved now. Its tokens go to the device
        // that asked, which redeems them itself: this page gets none.
        if (device) {
            if (uiResult?.pushToken && config.brokerUrl && (uiResult.trustDevice || deviceTrusted)) {
                sessions.saveDeviceHint(uiResult.pushToken, config.brokerUrl,
                    uiResult.deviceLabel ?? deviceLabels.get(uiResult.pushToken));
            }
            window.parent.postMessage(
                { type: 'privasys:result', result: { approved: true, sessionToken: '', method: 'wallet', sessionId: oidcSessionId } },
                parentOrigin,
            );
            return;
        }
        const tokens = await exchangeCode(idpBase, code, clientId, codeVerifier);

        // A link ends here. The page gets the ID token and nothing
        // else: no session is kept, so the one the person already
        // has for this client stands, and the access token of the
        // linked identity never leaves this frame.
        if (linkNonce) {
            if (!tokens.id_token) throw new Error('The identity provider returned no ID token');
            if (uiResult?.pushToken && config.brokerUrl && (uiResult.trustDevice || deviceTrusted)) {
                sessions.saveDeviceHint(uiResult.pushToken, config.brokerUrl,
                    uiResult.deviceLabel ?? deviceLabels.get(uiResult.pushToken));
            }
            window.parent.postMessage(
                { type: 'privasys:result', result: { linked: true, idToken: tokens.id_token, method: 'wallet', sessionId: oidcSessionId } },
                parentOrigin,
            );
            return;
        }

        // 6. Store session with JWT access_token and refresh_token.
        // `requestedAttributes`/`scope` record the RAW request this
        // session was minted for; connect() compares future configs
        // against them to detect a widened request. A step-up push
        // completion has no ceremony result, so the wallet push
        // binding carries over from the prior session.
        const session: AuthSession = {
            token: tokens.access_token,
            rpId,
            origin: config.apiBase ?? '',
            authenticatedAt: Date.now(),
            pushToken: uiResult?.pushToken ?? priorSession?.pushToken,
            // The marker, or a ceremony that brought the wallet's
            // sealed binding, so a wallet user is never taken for
            // someone without one.
            wallet: tokenSaysWallet(tokens.access_token)
                || !!uiResult?.sessionRelay || !!uiResult?.completedViaPoll,
            brokerUrl: config.brokerUrl || priorSession?.brokerUrl || '',
            refreshToken: tokens.refresh_token,
            clientId,
            requestedAttributes: [...(config.attributes ?? [])],
            scope: scopeStr,
        };
        sessions.store(initKey, session);
        if (session.pushToken && session.brokerUrl) {
            if (uiResult?.trustDevice || deviceTrusted) {
                // A wallet found through the popup keeps the name it has there.
                // The wallet's own name for the phone wins: it is current.
                sessions.saveDeviceHint(session.pushToken, session.brokerUrl,
                    uiResult?.deviceLabel ?? deviceLabels.get(session.pushToken));
            }
        }
        scheduleRenewal(initKey, session, parentOrigin);

        // Install the sealed session so the parent's `frame.session()`
        // RPC works once the auth result lands.
        //
        // The session the app gets is established from the wallet's
        // EncAuth voucher, never from the wallet's own bootstrap: only
        // a voucher-backed bootstrap carries the caller's identity
        // (X-Privasys-Sub), and an app that attributes callers answers
        // an anonymous session 401 right after a successful sign-in.
        // The wallet uploads the voucher before relaying the result;
        // the bounded wait covers an older wallet that uploads after,
        // and the same-device flow, where the tab is backgrounded
        // during the app switch and the upload lands on the way back.
        const wantsSealed = !!config.sessionRelay?.appHost
            && (!!uiResult?.sessionRelay || !!uiResult?.completedViaPoll);
        if (wantsSealed && uiResult) {
            const appHost = config.sessionRelay!.appHost;
            const session = await resumeVoucherSession(
                appHost,
                initKey,
                uiResult.completedViaPoll ? SAME_DEVICE_VOUCHER_WINDOW_MS : CEREMONY_VOUCHER_WINDOW_MS,
            );
            if (session) {
                sealed.pending = null;
                adoptSession(appHost, session, 0, parentOrigin);
                uiResult.sessionRelay = { sessionId: session.sessionId, encPub: '', expiresAt: 0 };
                window.parent.postMessage({
                    type: 'privasys:session:ready',
                    sessionId: session.sessionId,
                    appHost,
                    expiresAt: 0,
                }, parentOrigin);
            } else if (uiResult.sessionRelay) {
                // No voucher landed in time. Fall back to the wallet's
                // bootstrap so the app still gets a sealed channel,
                // anonymous to the app until the voucher lands: the
                // session keeps looking for it, and an app's 401
                // makes it look at once (PrivasysSession.identify).
                console.warn('[frame-host] no EncAuth voucher after the ceremony; installing the anonymous session');
                await installSessionRelay(uiResult.sessionRelay, parentOrigin);
            }
        }

        // 7. Send result to parent with the access_token. A step-up
        // push completion has no ceremony result — synthesise the
        // wallet-shaped minimum (the parent reads accessToken).
        const baseResult: SignInResult = uiResult ?? {
            sessionToken: tokens.access_token,
            method: 'wallet',
            sessionId: oidcSessionId,
        };
        window.parent.postMessage(
            {
                type: 'privasys:result',
                result: {
                    ...baseResult,
                    accessToken: tokens.access_token,
                },
            },
            parentOrigin,
        );
    } catch (err) {
        const msg = err instanceof Error ? err.message : 'Authentication failed';
        if (isGateOutcome(msg)) {
            // The gate shows how it ended and stays on it.
            window.parent.postMessage({ type: 'privasys:result', result: gateOutcomeResult(msg) }, parentOrigin);
        } else if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
            window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
        } else {
            const errorCode = err instanceof Error
                ? (err as Error & { code?: string }).code
                : undefined;
            window.parent.postMessage(
                { type: 'privasys:error', error: msg, ...(errorCode ? { errorCode } : {}) },
                parentOrigin,
            );
        }
    } finally {
        activeUI = null;
    }
    return;
}

// A headless page's choice: only the embedding page may make it, and
// the gate itself checks it against what it offers.
export async function onGateStart({ data }: MessageContext): Promise<void> {
    const choice = sanitiseChoice(data.choice);
    if (choice && activeUI) activeUI.start(choice);
    return;
}
