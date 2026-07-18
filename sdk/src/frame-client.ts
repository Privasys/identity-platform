// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Frame client — lightweight script loaded by adopter sites.
 *
 * Creates an invisible full-viewport iframe pointing to privasys.id/auth/
 * and communicates via postMessage. The authentication UI runs entirely
 * inside the iframe (on privasys.id's origin), which means:
 *
 *  - Sessions persist in privasys.id's localStorage across all adopter sites
 *  - Auth UI updates deploy once to privasys.id and apply everywhere
 *  - Session tokens are never stored in the adopter's origin
 *
 * Usage:
 * ```html
 * <script src="https://privasys.id/auth/privasys-auth-client.js"></script>
 * <script>
 *   const auth = new Privasys.AuthFrame({
 *     apiBase: 'https://api.developer.privasys.org',
 *     appName: 'my-app',
 *   });
 *   const result = await auth.signIn();
 *   console.log(result.sessionToken);
 * </script>
 * ```
 */

// ---------------------------------------------------------------------------
// Types (subset — avoids importing the full SDK)
// ---------------------------------------------------------------------------

/**
 * Supported OIDC scope tokens.
 *
 * These must stay in sync with:
 *   - IdP discovery (`scopes_supported` in oidc.go HandleDiscovery)
 *   - IdP scope→attribute mapping (`filterAttributesByScope` in oidc.go)
 *   - Wallet canonical attributes (`CANONICAL_ATTRIBUTES` in attributes.ts)
 *
 * | Scope            | Attributes granted                                      |
 * |------------------|---------------------------------------------------------|
 * | `openid`         | `sub` (always implied)                                  |
 * | `email`          | `email`, `email_verified`                               |
 * | `profile`        | `name`, `given_name`, `family_name`, `picture`, `locale`|
 * | `phone`          | `phone_number`                                          |
 * | `identity`       | Gov-verified document claims (`age_over_18`,            |
 * |                  | `age_over_21`, `nationality`, `birthdate`, …) — each    |
 * |                  | arrives as an enclave-signed SD-JWT VC, surfaced in     |
 * |                  | {@link SignInResult.disclosures}. Requires the client   |
 * |                  | to be registered billable; sign-in rejects with         |
 * |                  | {@link InsufficientCreditsError} when out of credits.   |
 * | `offline_access` | Issues a refresh token (no attributes)                  |
 */
export type PrivasysScope = 'openid' | 'email' | 'profile' | 'phone' | 'identity' | 'offline_access';

/**
 * A gov-verified attribute disclosure — an enclave-signed SD-JWT VC
 * (`typ: dc+sd-jwt`) minted by the Privasys identity-verifier enclave from a
 * government document, never a hand-typed value.
 *
 * Store {@link token} as the durable compliance receipt: it is offline
 * re-verifiable (issuer JWKS at `{issuer}/.well-known/jwt-vc-issuer`) and its
 * `evidence` ties the claim to the attested enclave measurement and the paid
 * disclosure ceremony (`evidence.voucher` ↔ ledger reservation).
 */
export interface AttributeDisclosure {
    /** Canonical attribute key, e.g. `"age_over_18"` or `"nationality"`. */
    claim: string;
    /** Disclosed value from the credential payload (e.g. `true`, `"GBR"`). */
    value: unknown;
    /** Assurance level — `"gov"` for document-verified claims. */
    assurance?: string;
    /** Issuance evidence: `ivr`, `measurement`, `issuing_state`, `verified_at`, `voucher`. */
    evidence?: Record<string, unknown>;
    /** Credential issuer (the verifier enclave origin). */
    issuer?: string;
    /** Epoch seconds the credential was issued. */
    issuedAt?: number;
    /** Epoch seconds the credential expires (short-lived by design — the
     *  stored token remains the receipt of what was verified at `issuedAt`). */
    expiresAt?: number;
    /** The raw SD-JWT VC. Persist this, not just the value. */
    token: string;
}

/**
 * Sign-in was rejected because the relying party's billing account cannot
 * cover the requested gov-verified attributes (IdP `402 insufficient_credits`).
 * The user was never prompted; top up the account and retry.
 */
/** Typed failure from {@link AuthFrame.connect}. */
export class ConnectError extends Error {
    /** 'cancelled' — the user dismissed the ceremony; 'timeout' — the
     *  approval/ceremony was not completed in time; 'failed' — anything
     *  else (transport, enclave unavailable, IdP error). */
    readonly code: 'cancelled' | 'timeout' | 'failed';
    constructor(code: 'cancelled' | 'timeout' | 'failed', message: string) {
        super(message);
        this.name = 'ConnectError';
        this.code = code;
    }
}

/** Successful outcome of {@link AuthFrame.connect}. */
export interface ConnectResult {
    /** JWT access token for the session (existing or freshly minted). */
    accessToken: string;
    /** Sealed transport proxy — null when `sessionRelay` is not configured. */
    session: SealedSession | null;
    /** Full ceremony result when an interactive sign-in ran; absent when
     *  the session was restored silently (no UI was shown). */
    result?: SignInResult;
}

export class InsufficientCreditsError extends Error {
    readonly code = 'insufficient_credits';
    constructor(message?: string) {
        super(message || 'Insufficient credits for the requested attributes');
        this.name = 'InsufficientCreditsError';
    }
}

export interface AuthFrameConfig {
    /** Management service API base URL. */
    apiBase: string;
    /** App name or UUID as registered on the platform. */
    appName: string;
    /** Relying party ID. Defaults to appName. */
    rpId?: string;
    /** WebSocket URL for the auth broker relay. */
    brokerUrl?: string;
    /** Timeout in ms (default: 120 000). */
    timeout?: number;
    /** Origin of the auth iframe (default: "https://privasys.id"). */
    authOrigin?: string;
    /** OIDC client_id — when set, the iframe runs an OIDC PKCE flow and
     *  returns a signed JWT access_token (instead of an opaque session token). */
    clientId?: string;
    /**
     * OIDC scopes to request from the IdP `/authorize` endpoint.
     * Controls which attributes the wallet will prompt for.
     * `'openid'` is always included automatically.
     *
     * @default ['openid', 'offline_access']
     * @example ['openid', 'email', 'profile', 'offline_access']
     *
     * @see {@link PrivasysScope} for the full list of supported scope tokens.
     */
    scope?: readonly PrivasysScope[];
    /** URL to the app's privacy policy. Shown to the user when sharing attributes. */
    privacyPolicyUrl?: string;
    /**
     * Mount the auth iframe inside this element instead of as a full-screen
     * modal overlay.  The iframe fills the container (width/height: 100%).
     * The container should have explicit dimensions (min-height 560px).
     *
     * Passing a container implies `presentation: 'inline'` — the hosted
     * auth page drops its own brand panel and close button and renders a
     * single compact column sized for the container. The host page owns
     * dismissal via {@link AuthFrame.cancel}.
     */
    container?: HTMLElement;
    /**
     * Presentation mode of the hosted auth page. Defaults to `'inline'`
     * when a `container` is set, `'modal'` otherwise. Set explicitly to
     * override that inference. `'page'` makes the SDK render the WHOLE
     * gate — the two-column layout with your `pitch` content, SDK-styled,
     * in the left panel — filling the container (or the viewport when no
     * container is given).
     */
    presentation?: 'modal' | 'inline' | 'page';
    /**
     * Content for the gate's left panel in `'page'` presentation. Plain
     * strings only — rendered as text and length-capped by the hosted
     * page (title 120, description 600, up to 5 bullets of 200 chars).
     * `logoUrl` (https only) shows your logo above the title.
     */
    pitch?: { title?: string; description?: string; bullets?: string[]; logoUrl?: string };
    /**
     * Which sign-in methods the ceremony offers. Defaults to all
     * available. A site that already showed its own identity chooser
     * (e.g. "Connect with Privasys" next to "Connect with Google")
     * passes `['wallet']`: the menu screen is skipped and the wallet
     * flow starts immediately (push when the device is trusted, QR
     * otherwise).
     */
    methods?: readonly ('wallet' | 'passkey' | 'social')[];
    /**
     * Your app's identity for the gate header (`'page'` presentation):
     * your logo (https only) and display name lead the header, with
     * "Secured by Privasys ID" as the trust seal and a Close control
     * that rejects `connect()` with code 'cancelled'. `displayName`
     * defaults to a prettified `appName`.
     */
    app?: { logoUrl?: string; displayName?: string };
    /**
     * Sealed session-relay opt-in. When set, the auth iframe negotiates an
     * end-to-end ECDH session with the enclave at `appHost` during the
     * wallet ceremony. After `signIn()` resolves, call {@link AuthFrame.session}
     * to obtain a proxy that issues sealed CBOR-AES-GCM requests; the iframe
     * stays mounted (hidden) so the SDK private key stays inside
     * `authOrigin` and never reaches the adopter's origin.
     */
    sessionRelay?: { appHost: string };
}

export interface SignInResult {
    sessionToken: string;
    method: 'wallet' | 'passkey';
    attestation?: Record<string, unknown>;
    sessionId: string;
    pushToken?: string;
    /** JWT access_token from the IdP (present when clientId was set in config). */
    accessToken?: string;
    /**
     * Gov-verified attribute disclosures (present when the `identity` scope
     * was requested and the user approved sharing). Each entry carries the
     * decoded claim/value plus the raw SD-JWT VC to persist as a receipt.
     */
    disclosures?: AttributeDisclosure[];
    /** Wallet-attested sealed-transport binding (set when sessionRelay was configured). */
    sessionRelay?: { sessionId: string; encPub: string; expiresAt?: number };
}

/**
 * Sealed-transport request response. `body` is the deserialised CBOR
 * payload returned by the enclave (typically a `Uint8Array` plaintext
 * carrying JSON), `headers` mirrors the HTTP response headers, and
 * `sealed` is true when the response actually came back encrypted (false
 * means the enclave returned a non-sealed status, e.g. 4xx error).
 */
export interface SealedResponse {
    status: number;
    headers: Record<string, string>;
    body: Uint8Array;
    sealed: boolean;
}

/**
 * Streaming variant of {@link SealedResponse}. Yields decrypted plaintext
 * chunks (already past the gateway's terminate path) as they arrive.
 */
export interface SealedStreamResponse {
    status: number;
    sealed: boolean;
    headers: Record<string, string>;
    body: ReadableStream<Uint8Array>;
}

/**
 * Proxy for issuing sealed requests against the enclave. Returned by
 * {@link AuthFrame.session}.
 */
export interface SealedSession {
    sessionId: string;
    appHost: string;
    expiresAt: number;
    request(method: string, path: string, body?: unknown, init?: RequestInit): Promise<SealedResponse>;
    /**
     * Streaming variant of {@link request}. Use for SSE / chunked responses
     * (e.g. OpenAI-style chat completions). The returned `body` yields
     * decrypted plaintext bytes; SSE event parsing is left to the caller.
     */
    stream(method: string, path: string, body?: unknown, init?: RequestInit): Promise<SealedStreamResponse>;
}

// ---------------------------------------------------------------------------
// AuthFrame
// ---------------------------------------------------------------------------

/**
 * Reduce a `RequestInit` to the subset that survives `postMessage`'s
 * structured clone. AbortSignal and Headers instances both throw
 * `DataCloneError`, so we drop the signal entirely (the caller-side
 * forwards aborts via an explicit `stream-cancel` message) and flatten
 * Headers to a plain record.
 */
function sanitizeInit(init?: RequestInit): { headers?: Record<string, string> } | undefined {
    if (!init) return undefined;
    const out: { headers?: Record<string, string> } = {};
    if (init.headers) {
        const h: Record<string, string> = {};
        if (init.headers instanceof Headers) {
            init.headers.forEach((v, k) => { h[k] = v; });
        } else if (Array.isArray(init.headers)) {
            for (const [k, v] of init.headers) h[k] = v;
        } else {
            Object.assign(h, init.headers as Record<string, string>);
        }
        out.headers = h;
    }
    return out;
}

/** Decode a base64url JSON segment (JWT header/payload). */
function b64uJson(seg: string): Record<string, unknown> {
    const b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? b64 + '='.repeat(4 - (b64.length % 4)) : b64;
    return JSON.parse(atob(pad));
}

/** SD-JWT VC serialisation: a compact JWS followed by `~` (no disclosures). */
const SD_JWT_RE = /^eyJ[\w-]*\.[\w-]+\.[\w-]+~$/;

/**
 * Pull gov-attribute disclosures out of an IdP access token. The wallet
 * relays each gov claim as an enclave-signed SD-JWT VC in place of a raw
 * value, so any claim whose value parses as one is a disclosure. Decoding
 * here is presentation only — verification is the JWS signature against the
 * issuer's JWKS, done server-side or at audit time.
 */
function extractDisclosures(accessToken?: string): AttributeDisclosure[] | undefined {
    if (!accessToken) return undefined;
    let claims: Record<string, unknown>;
    try {
        claims = b64uJson(accessToken.split('.')[1]);
    } catch {
        return undefined;
    }
    const out: AttributeDisclosure[] = [];
    for (const [key, raw] of Object.entries(claims)) {
        if (typeof raw !== 'string' || !SD_JWT_RE.test(raw)) continue;
        try {
            const vc = b64uJson(raw.slice(0, -1).split('.')[1]);
            out.push({
                claim: typeof vc.claim === 'string' ? vc.claim : key,
                value: vc.value,
                assurance: typeof vc.assurance === 'string' ? vc.assurance : undefined,
                evidence: (vc.evidence && typeof vc.evidence === 'object')
                    ? vc.evidence as Record<string, unknown>
                    : undefined,
                issuer: typeof vc.iss === 'string' ? vc.iss : undefined,
                issuedAt: typeof vc.iat === 'number' ? vc.iat : undefined,
                expiresAt: typeof vc.exp === 'number' ? vc.exp : undefined,
                token: raw,
            });
        } catch { /* value merely looked like a JWS — not a credential, skip */ }
    }
    return out.length ? out : undefined;
}

export class AuthFrame {
    private readonly authOrigin: string;
    private readonly config: Omit<AuthFrameConfig, 'authOrigin' | 'container'>;
    private readonly container: HTMLElement | null;
    private sessionIframe: HTMLIFrameElement | null = null;
    private sessionHandler: ((e: MessageEvent) => void) | null = null;
    // Cached session payload from the last successful getSession() call.
    // Reused while sessionIframe is still attached so concurrent callers
    // (e.g. multiple attestation rows minting per-audience tokens) don't
    // tear down each other's iframe via destroySessionIframe().
    private cachedSession: { token: string; rpId: string; authenticatedAt: number } | null = null;
    private sessionInFlight: Promise<{ token: string; rpId: string; authenticatedAt: number } | null> | null = null;
    private _onSessionExpired?: (rpId: string) => void;
    private _onSessionRenewed?: (rpId: string, accessToken?: string) => void;
    // Tears down the in-flight signIn() ceremony (set while one is active).
    private cancelSignIn: (() => void) | null = null;
    // connect()'s hint for the frame host: run the approve-only flow (with
    // the resume-rejection reason) before falling back to the ceremony.
    private connectHint: { mode: 'approve'; reason: string | null } | null = null;
    // Sealed session-relay state.
    private sealedIframe: HTMLIFrameElement | null = null;
    private sealedHandler: ((e: MessageEvent) => void) | null = null;
    private sealedSession: SealedSession | null = null;
    private sealedReadyResolvers: Array<(s: SealedSession) => void> = [];
    private sealedReadyRejecters: Array<(e: Error) => void> = [];
    private sealedReqSeq = 0;
    private sealedReqs = new Map<number, { resolve: (r: SealedResponse) => void; reject: (e: Error) => void }>();
    private sealedStreams = new Map<number, {
        controller?: ReadableStreamDefaultController<Uint8Array>;
        resolve?: (r: SealedStreamResponse) => void;
        reject?: (e: Error) => void;
    }>();

    constructor(config: AuthFrameConfig) {
        const { authOrigin, container, ...rest } = config;
        this.authOrigin = authOrigin ?? 'https://privasys.id';
        this.container = container ?? null;
        this.config = rest;
    }

    /** The RP ID used for authentication. */
    get rpId(): string {
        return this.config.rpId ?? this.config.appName;
    }

    /** Register a callback for when the session expires (renewal failed). */
    set onSessionExpired(cb: ((rpId: string) => void) | undefined) {
        this._onSessionExpired = cb;
    }

    /** Register a callback for when the session is silently renewed. */
    set onSessionRenewed(cb: ((rpId: string, accessToken?: string) => void) | undefined) {
        this._onSessionRenewed = cb;
    }

    /**
     * Cancel an in-flight {@link signIn} ceremony. The pending promise
     * rejects with "Authentication cancelled" and the auth iframe is
     * removed. Intended for inline embeds (`container` set), where the
     * hosted page renders no close button and dismissal belongs to the
     * host page. No-op when no ceremony is in flight.
     */
    cancel(): void {
        this.cancelSignIn?.();
    }

    /**
     * One-call session acquisition — the API adopters should use instead
     * of hand-rolling restore/approval/sign-in logic. In order:
     *
     *   1. Silent restore: an existing OIDC session (cross-site SSO) plus,
     *      when `sessionRelay` is configured, the sealed session resumed
     *      from the stored EncAuth voucher. No UI is shown.
     *   2. Re-approval: the session exists but the enclave refused (its
     *      measurement changed after a redeploy) or lost the voucher — the
     *      gate renders the one-tap wallet approval, falling back to the
     *      full ceremony if it can't complete.
     *   3. Full sign-in ceremony.
     *
     * The gate renders per `presentation`/`pitch`/`methods` config.
     * Resolves with the access token and (when `sessionRelay` is set) the
     * live {@link SealedSession}; rejects with a {@link ConnectError}
     * (`cancelled` | `timeout` | `failed`). To retry after a failure, call
     * `connect()` again.
     */
    async connect(): Promise<ConnectResult> {
        const appHost = this.config.sessionRelay?.appHost;
        this.connectHint = null;

        // 1. Silent restore.
        const existing = await this.getSession().catch(() => null);
        if (existing?.token) {
            if (!appHost) {
                return { accessToken: existing.token, session: null };
            }
            try {
                const sealed = await this.resumeSession();
                return { accessToken: existing.token, session: sealed };
            } catch (err) {
                const msg = (err as Error).message ?? '';
                if (msg.startsWith('rejected') || msg.startsWith('no-voucher')) {
                    // 2. Interactive re-approval (the gate falls back to the
                    // full ceremony internally when it can't complete).
                    const colon = msg.indexOf(':');
                    this.connectHint = {
                        mode: 'approve',
                        reason: colon > 0 ? msg.slice(colon + 1) : null,
                    };
                } else {
                    // Transient transport failure (enclave down/booting) — a
                    // ceremony would not help; the caller retries connect().
                    throw new ConnectError('failed', msg || 'sealed resume failed');
                }
            }
        }

        // 3. Interactive gate (approve-first when hinted, else ceremony).
        try {
            const result = await this.signIn();
            // Only await the sealed proxy when the ceremony actually bound
            // one — session() otherwise waits forever (there is nothing to
            // resolve it) and would park connect() indefinitely.
            const session = (this.config.sessionRelay && result.sessionRelay)
                ? await this.session().catch(() => null)
                : null;
            if (this.config.sessionRelay && !session) {
                // The ceremony completed via a method that cannot open the
                // sealed channel (social/passkey — possible only when the
                // adopter explicitly overrode methods). Fail loudly: a
                // token without the sealed transport is useless to a
                // session-relay app and reads as a silent dead end.
                throw new ConnectError('failed',
                    'This app requires the Privasys Wallet: the sign-in method used cannot open a sealed channel to it.');
            }
            const accessToken = result.accessToken ?? result.sessionToken;
            return { accessToken, session, result };
        } catch (err) {
            if (err instanceof ConnectError) throw err;
            const msg = err instanceof Error ? err.message : String(err);
            if (msg === 'Authentication cancelled') {
                throw new ConnectError('cancelled', msg);
            }
            if (/timeout|timed out/i.test(msg)) {
                throw new ConnectError('timeout', msg);
            }
            throw new ConnectError('failed', msg);
        } finally {
            this.connectHint = null;
        }
    }

    /**
     * Open the authentication modal (inside a privasys.id iframe) and
     * wait for the user to complete the ceremony.
     */
    signIn(): Promise<SignInResult> {
        return new Promise<SignInResult>((resolve, reject) => {
            const iframe = document.createElement('iframe');
            iframe.src = this.authOrigin + '/auth/';

            const wantsSealed = !!this.config.sessionRelay?.appHost;

            // Sealed mode requires the auth iframe to outlive the sign-in
            // ceremony (subsequent `session().request()` / `.stream()` calls
            // route through its contentWindow). If the caller passes a
            // `container`, React will eventually unmount that container and
            // the iframe along with it — at which point `contentWindow`
            // becomes null and every sealed call throws "AuthFrame: sealed
            // iframe is gone". We can't move the iframe across parents
            // later (browsers reload an iframe whose parent changes, which
            // would destroy the in-memory ECDH session keys), so for sealed
            // mode we always attach to <body> from the start. To preserve
            // the inline visual, we absolute-position the iframe over the
            // container's bounding rect and follow it on resize/scroll
            // until sign-in completes; once auth resolves we shrink the
            // iframe to 0×0 (invisible) but leave it parented to <body>.
            const overlayContainer = wantsSealed ? this.container : null;
            const reflowOverlay = (): void => {
                if (!overlayContainer) return;
                const r = overlayContainer.getBoundingClientRect();
                iframe.style.cssText =
                    `position:fixed;left:${r.left}px;top:${r.top}px;` +
                    `width:${r.width}px;height:${r.height}px;` +
                    'z-index:999998;border:none;background:#fff;';
            };
            let overlayHandlers: (() => void) | null = null;
            const stopOverlay = (): void => {
                if (overlayHandlers) {
                    overlayHandlers();
                    overlayHandlers = null;
                }
            };

            if (overlayContainer) {
                // Sealed + container: absolute overlay on <body>.
                reflowOverlay();
                iframe.allow =
                    'publickey-credentials-get *; publickey-credentials-create *';
                document.body.appendChild(iframe);
                window.addEventListener('resize', reflowOverlay);
                window.addEventListener('scroll', reflowOverlay, true);
                const ro = typeof ResizeObserver !== 'undefined'
                    ? new ResizeObserver(reflowOverlay)
                    : null;
                ro?.observe(overlayContainer);
                overlayHandlers = () => {
                    window.removeEventListener('resize', reflowOverlay);
                    window.removeEventListener('scroll', reflowOverlay, true);
                    ro?.disconnect();
                };
            } else if (this.container) {
                // Embedded mode (non-sealed): fill the container element
                iframe.style.cssText =
                    'width:100%;height:100%;border:none;display:block;';
                iframe.allow =
                    'publickey-credentials-get *; publickey-credentials-create *';
                this.container.appendChild(iframe);
            } else {
                // Modal mode (default): full-screen overlay
                iframe.style.cssText =
                    'position:fixed;inset:0;width:100%;height:100%;' +
                    'z-index:999999;border:none;background:#fff;';
                iframe.allow =
                    'publickey-credentials-get *; publickey-credentials-create *';
                document.body.appendChild(iframe);
            }

            // When session-relay is on we keep the iframe mounted (hidden)
            // after auth completes so subsequent `session().request()` calls
            // can route through the iframe-resident PrivasysSession. Without
            // session-relay we tear everything down on result.
            const finishSignIn = (result: SignInResult) => {
                this.cancelSignIn = null;
                if (wantsSealed) {
                    stopOverlay();
                    // Hide the iframe but leave it parented to <body> with
                    // the message handler still attached.
                    iframe.style.cssText =
                        'position:fixed;width:0;height:0;border:none;opacity:0;pointer-events:none;';
                    this.sealedIframe = iframe;
                    this.sealedHandler = handler;
                    resolve(result);
                } else {
                    cleanup();
                    resolve(result);
                }
            };

            const cleanup = () => {
                stopOverlay();
                window.removeEventListener('message', handler);
                iframe.remove();
                this.cancelSignIn = null;
            };

            // Host-page-initiated cancel (inline embeds have no close
            // button). Removing the iframe tears down the ceremony —
            // broker WebSocket included; the IdP session expires by TTL,
            // exactly as when the user dismisses the modal's X.
            this.cancelSignIn = () => {
                cleanup();
                reject(new Error('Authentication cancelled'));
            };

            const handler = (e: MessageEvent) => {
                if (e.origin !== this.authOrigin) return;
                // Multiple privasys.id iframes can coexist (this signIn
                // iframe, getSession()'s SSO check iframe, and others).
                // Without filtering by source, a `privasys:ready` from
                // the SSO iframe would re-trigger `privasys:init` here
                // → restart the OIDC ceremony in our hidden sealed
                // iframe → second push notification → second Face ID
                // prompt on the wallet after `Trust this device`.
                if (e.source !== iframe.contentWindow) return;
                const data = e.data;
                if (!data || typeof data.type !== 'string') return;

                switch (data.type) {
                    case 'privasys:ready': {
                        const presentation = this.config.presentation
                            ?? (this.container ? 'inline' : 'modal');
                        // Methods pass through as configured; when absent the
                        // frame host filters them by attribute capability
                        // (essential attributes hide methods that cannot
                        // deliver them). Wallet-less sign-in is a supported,
                        // deliberately degraded mode — never blanket-blocked.
                        iframe.contentWindow!.postMessage(
                            {
                                type: 'privasys:init',
                                config: {
                                    ...this.config,
                                    presentation,
                                    // Capabilities this client handles; the host
                                    // only uses features the client declared.
                                    caps: ['parent-navigate'],
                                    ...(this.connectHint ? { connect: this.connectHint } : {}),
                                },
                            },
                            this.authOrigin,
                        );
                        break;
                    }

                    case 'privasys:result': {
                        const result = data.result as SignInResult;
                        const disclosures = extractDisclosures(result.accessToken);
                        if (disclosures) result.disclosures = disclosures;
                        finishSignIn(result);
                        break;
                    }

                    case 'privasys:navigate': {
                        // Mobile wallet handoff: the custom-scheme navigation
                        // must be TOP-LEVEL and FIRST-PARTY. WebKit blocks
                        // custom-scheme navigations initiated by cross-origin
                        // iframes (Safari shows "address is invalid" even
                        // with the app installed), so the adopter page — this
                        // window — performs it. The tap in the iframe grants
                        // transient user activation to ancestors, and an
                        // external-protocol navigation does not unload the
                        // page, so the ceremony keeps running.
                        const url = String(data.url || '');
                        if (/^privasys-wallet(-dev|-preview)?:\/\//.test(url)) {
                            window.location.href = url;
                        }
                        break;
                    }

                    case 'privasys:cancel':
                        cleanup();
                        reject(new Error('Authentication cancelled'));
                        break;

                    case 'privasys:error':
                        cleanup();
                        reject(data.errorCode === 'insufficient_credits'
                            ? new InsufficientCreditsError(data.error)
                            : new Error(data.error || 'Authentication failed'));
                        break;

                    case 'privasys:session:ready': {
                        const s = this.installSealedProxy({
                            sessionId: data.sessionId,
                            appHost: data.appHost,
                            expiresAt: data.expiresAt ?? 0,
                        });
                        const resolvers = this.sealedReadyResolvers;
                        this.sealedReadyResolvers = [];
                        this.sealedReadyRejecters = [];
                        for (const r of resolvers) r(s);
                        break;
                    }

                    case 'privasys:session:error': {
                        const err = new Error(data.error || 'sealed session failed');
                        const rejecters = this.sealedReadyRejecters;
                        this.sealedReadyResolvers = [];
                        this.sealedReadyRejecters = [];
                        for (const r of rejecters) r(err);
                        break;
                    }

                    default:
                        this.handleSealedRpcMessage(data);
                }
            };

            window.addEventListener('message', handler);
        });
    }

    /**
     * Returns the sealed session installed by the most recent successful
     * `signIn()` (when `sessionRelay` was configured). Resolves once the
     * iframe-side ECDH handshake completes — usually right after `signIn()`
     * resolves, but slightly later if the wallet returned the binding only
     * just before this call.
     */
    session(): Promise<SealedSession> {
        if (this.sealedSession) return Promise.resolve(this.sealedSession);
        if (!this.config.sessionRelay?.appHost) {
            return Promise.reject(new Error('AuthFrame: session() requires sessionRelay config'));
        }
        return new Promise<SealedSession>((resolve, reject) => {
            this.sealedReadyResolvers.push(resolve);
            this.sealedReadyRejecters.push(reject);
        });
    }

    /**
     * Handle sealed-transport RPC responses relayed from the auth iframe.
     * Shared by the sign-in message handler (sealed mode) and the
     * resume-session handler. Returns true when the message was consumed.
     */
    private handleSealedRpcMessage(data: { type?: unknown; [k: string]: unknown }): boolean {
        switch (data.type) {
            case 'privasys:session:response': {
                const id = data.id as number;
                const pending = this.sealedReqs.get(id);
                if (!pending) return true;
                this.sealedReqs.delete(id);
                if (data.error) {
                    pending.reject(new Error(String(data.error)));
                } else {
                    pending.resolve({
                        status: data.status as number,
                        headers: (data.headers as Record<string, string>) || {},
                        body: data.body as Uint8Array,
                        sealed: !!data.sealed,
                    });
                }
                return true;
            }

            case 'privasys:session:stream-start': {
                const id = data.id as number;
                const slot = this.sealedStreams.get(id);
                if (!slot || !slot.resolve) return true;
                const stream = new ReadableStream<Uint8Array>({
                    start: (controller) => { slot.controller = controller; },
                    cancel: () => {
                        this.sealedStreams.delete(id);
                        this.sealedIframe?.contentWindow?.postMessage(
                            { type: 'privasys:session:stream-cancel', id },
                            this.authOrigin,
                        );
                    },
                });
                slot.resolve({
                    status: data.status as number,
                    sealed: !!data.sealed,
                    headers: (data.headers as Record<string, string>) || {},
                    body: stream,
                });
                slot.resolve = undefined;
                slot.reject = undefined;
                return true;
            }

            case 'privasys:session:stream-chunk': {
                const id = data.id as number;
                const slot = this.sealedStreams.get(id);
                if (!slot?.controller) return true;
                const chunk = data.chunk as Uint8Array;
                if (chunk && chunk.byteLength > 0) {
                    slot.controller.enqueue(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
                }
                return true;
            }

            case 'privasys:session:stream-end': {
                const id = data.id as number;
                const slot = this.sealedStreams.get(id);
                if (!slot) return true;
                slot.controller?.close();
                this.sealedStreams.delete(id);
                return true;
            }

            case 'privasys:session:stream-error': {
                const id = data.id as number;
                const slot = this.sealedStreams.get(id);
                if (!slot) return true;
                const err = new Error(String(data.error || 'sealed stream failed'));
                if (slot.reject) {
                    slot.reject(err);
                } else {
                    slot.controller?.error(err);
                }
                this.sealedStreams.delete(id);
                return true;
            }

            default:
                return false;
        }
    }

    /**
     * Re-establish the sealed session after a page reload, with no wallet
     * ceremony and no push notification. Mounts a hidden auth iframe and
     * asks the frame-host to bootstrap against the enclave using the
     * EncAuth voucher stored at the IdP (Phase D silent rebind, cold-start
     * variant).
     *
     * Rejects with `no-voucher` (the user never completed a sealed sign-in
     * for this app), `rejected` (the enclave refused the voucher — a full
     * wallet ceremony is required), or `unavailable` (transient transport
     * failure, worth retrying). When the enclave reported WHY it refused,
     * the message is `rejected:<reason>` with reason one of
     * `workload-changed` (the app was updated), `enc-changed` (the hosting
     * platform changed), `voucher-expired`, `voucher-invalid` — so the app
     * can explain the wake instead of showing a generic re-sign-in prompt.
     */
    resumeSession(): Promise<SealedSession> {
        if (this.sealedSession) return Promise.resolve(this.sealedSession);
        if (!this.config.sessionRelay?.appHost) {
            return Promise.reject(new Error('AuthFrame: resumeSession() requires sessionRelay config'));
        }
        const appHost = this.config.sessionRelay.appHost;

        // A sealed iframe without an installed session is a leftover from
        // a failed handshake — rebuild from scratch.
        if (this.sealedIframe) this.destroySealedIframe();

        return new Promise<SealedSession>((resolve, reject) => {
            const iframe = document.createElement('iframe');
            iframe.src = this.authOrigin + '/auth/';
            iframe.style.cssText =
                'position:fixed;width:0;height:0;border:none;opacity:0;pointer-events:none;';
            const id = ++this.sealedReqSeq;
            let settled = false;

            const fail = (err: Error) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                window.removeEventListener('message', handler);
                iframe.remove();
                reject(err);
            };
            const timer = setTimeout(() => fail(new Error('unavailable')), 15_000);

            const handler = (e: MessageEvent) => {
                if (e.origin !== this.authOrigin) return;
                if (e.source !== iframe.contentWindow) return;
                const data = e.data;
                if (!data || typeof data.type !== 'string') return;
                // After adoption this same handler keeps serving the sealed
                // RPC traffic for the lifetime of the iframe.
                if (this.handleSealedRpcMessage(data)) return;

                if (data.type === 'privasys:ready') {
                    iframe.contentWindow!.postMessage(
                        { type: 'privasys:session:resume', id, appHost, rpId: this.rpId },
                        this.authOrigin,
                    );
                    return;
                }

                if (data.type === 'privasys:session:resume:response' && data.id === id) {
                    if (settled) return;
                    if (data.error) {
                        fail(new Error(
                            data.reason ? `${String(data.error)}:${String(data.reason)}` : String(data.error),
                        ));
                        return;
                    }
                    settled = true;
                    clearTimeout(timer);
                    // Adopt this iframe as the sealed transport carrier;
                    // the handler stays attached for RPC responses.
                    this.sealedIframe = iframe;
                    this.sealedHandler = handler;
                    resolve(this.installSealedProxy({
                        sessionId: String(data.sessionId),
                        appHost,
                        expiresAt: Number(data.expiresAt) || 0,
                    }));
                }
            };

            window.addEventListener('message', handler);
            document.body.appendChild(iframe);
        });
    }

    private installSealedProxy(meta: { sessionId: string; appHost: string; expiresAt: number }): SealedSession {
        const sealed: SealedSession = {
            sessionId: meta.sessionId,
            appHost: meta.appHost,
            expiresAt: meta.expiresAt,
            request: (method, path, body, init) => {
                if (!this.sealedIframe?.contentWindow) {
                    return Promise.reject(new Error('AuthFrame: sealed iframe is gone'));
                }
                const id = ++this.sealedReqSeq;
                const target = this.sealedIframe.contentWindow;
                // `init` may carry an AbortSignal (and a Headers instance).
                // Neither survives `postMessage`'s structured clone, so we
                // serialise to a plain { headers } object before sending.
                const safeInit = sanitizeInit(init);
                return new Promise<SealedResponse>((resolve, reject) => {
                    this.sealedReqs.set(id, { resolve, reject });
                    target.postMessage(
                        { type: 'privasys:session:request', id, method, path, body, init: safeInit },
                        this.authOrigin,
                    );
                });
            },
            stream: (method, path, body, init) => {
                if (!this.sealedIframe?.contentWindow) {
                    return Promise.reject(new Error('AuthFrame: sealed iframe is gone'));
                }
                const id = ++this.sealedReqSeq;
                const target = this.sealedIframe.contentWindow;
                const safeInit = sanitizeInit(init);
                const signal = init?.signal;
                return new Promise<SealedStreamResponse>((resolve, reject) => {
                    this.sealedStreams.set(id, { resolve, reject });
                    // If the caller passed an AbortSignal, forward an
                    // explicit cancel message to the iframe when it fires
                    // (the signal itself can't cross postMessage). We
                    // also reject the pending start promise if abort
                    // happens before stream-start arrives.
                    if (signal) {
                        const onAbort = () => {
                            try {
                                target.postMessage(
                                    { type: 'privasys:session:stream-cancel', id },
                                    this.authOrigin,
                                );
                            } catch { /* iframe may be gone */ }
                            const slot = this.sealedStreams.get(id);
                            if (slot?.reject) {
                                slot.reject(new DOMException('Aborted', 'AbortError'));
                                this.sealedStreams.delete(id);
                            } else if (slot?.controller) {
                                try { slot.controller.error(new DOMException('Aborted', 'AbortError')); } catch { /* */ }
                                this.sealedStreams.delete(id);
                            }
                        };
                        if (signal.aborted) {
                            queueMicrotask(onAbort);
                        } else {
                            signal.addEventListener('abort', onAbort, { once: true });
                        }
                    }
                    target.postMessage(
                        { type: 'privasys:session:stream-request', id, method, path, body, init: safeInit },
                        this.authOrigin,
                    );
                });
            },
        };
        this.sealedSession = sealed;
        return sealed;
    }

    /**
     * Check whether privasys.id already has a session for this RP.
     * Uses a hidden iframe to query localStorage on the auth origin.
     * The iframe is kept alive so the frame-host can run renewal timers.
     */
    getSession(): Promise<{ token: string; rpId: string; authenticatedAt: number } | null> {
        // Idempotent: if a session iframe is already attached AND we
        // have the cached payload from when it was set up, hand it
        // back directly. Tearing it down and recreating it would
        // break any concurrent caller about to postMessage through
        // the same iframe (e.g. getTokenForAudience), which is the
        // root cause of the "no active session iframe; call
        // getSession() first" race seen when multiple attestation
        // rows mint audience tokens in parallel.
        if (this.sessionIframe?.contentWindow && this.cachedSession) {
            return Promise.resolve(this.cachedSession);
        }
        // Coalesce concurrent in-flight calls.
        if (this.sessionInFlight) return this.sessionInFlight;
        const p = this.doGetSession();
        this.sessionInFlight = p;
        p.finally(() => { if (this.sessionInFlight === p) this.sessionInFlight = null; });
        return p;
    }

    private doGetSession(): Promise<{ token: string; rpId: string; authenticatedAt: number } | null> {
        return new Promise((resolve) => {
            // Clean up any prior session iframe for this instance
            this.destroySessionIframe();

            const iframe = document.createElement('iframe');
            iframe.src = this.authOrigin + '/auth/';
            iframe.style.cssText = 'position:fixed;width:0;height:0;border:none;opacity:0;pointer-events:none;';

            const timeout = setTimeout(() => {
                this.destroySessionIframe();
                resolve(null);
            }, 5000);

            const handler = (e: MessageEvent) => {
                if (e.origin !== this.authOrigin) return;
                if (e.source !== iframe.contentWindow) return;
                const data = e.data;
                if (!data || typeof data.type !== 'string') return;

                if (data.type === 'privasys:ready') {
                    iframe.contentWindow!.postMessage(
                        { type: 'privasys:check-session', rpId: this.rpId },
                        this.authOrigin,
                    );
                } else if (data.type === 'privasys:session') {
                    clearTimeout(timeout);

                    if (data.session) {
                        // Keep iframe alive so the frame-host can run renewal
                        // timers (OIDC refresh_token or legacy push-based).
                        this.sessionIframe = iframe;
                        this.sessionHandler = handler;
                        this.cachedSession = data.session;
                    } else {
                        // No session — clean up
                        window.removeEventListener('message', handler);
                        iframe.remove();
                        this.sessionIframe = null;
                        this.sessionHandler = null;
                        this.cachedSession = null;
                    }

                    resolve(data.session || null);
                } else if (data.type === 'privasys:session-renewed') {
                    // Keep the cached session in step with the background
                    // renewal so a subsequent getSession() returns the
                    // FRESH access token. Without this, getSession() keeps
                    // handing back the token captured at first mount;
                    // consumers that re-read on `onSessionRenewed` then
                    // present an already-expired token, 401, and surface a
                    // false "session expired" that a reload silently fixes.
                    if (this.cachedSession && typeof data.accessToken === 'string' && data.accessToken) {
                        this.cachedSession = {
                            ...this.cachedSession,
                            token: data.accessToken,
                            authenticatedAt: Date.now(),
                        };
                    }
                    this._onSessionRenewed?.(data.rpId, data.accessToken);
                } else if (data.type === 'privasys:session-expired') {
                    this._onSessionExpired?.(data.rpId);
                    this.destroySessionIframe();
                }
            };

            this.sessionHandler = handler;
            this.sessionIframe = iframe;
            window.addEventListener('message', handler);
            document.body.appendChild(iframe);
        });
    }

    /**
     * Clear the session for this RP from privasys.id localStorage.
     */
    clearSession(): Promise<void> {
        return new Promise((resolve) => {
            // If we have a persistent iframe, use it directly
            if (this.sessionIframe?.contentWindow) {
                const sessionWin = this.sessionIframe.contentWindow;
                const handler = (e: MessageEvent) => {
                    if (e.origin !== this.authOrigin) return;
                    if (e.source !== sessionWin) return;
                    if (e.data?.type === 'privasys:session-cleared') {
                        window.removeEventListener('message', handler);
                        this.destroySessionIframe();
                        resolve();
                    }
                };
                window.addEventListener('message', handler);
                this.sessionIframe.contentWindow.postMessage(
                    { type: 'privasys:clear-session', rpId: this.rpId },
                    this.authOrigin,
                );
                setTimeout(() => {
                    window.removeEventListener('message', handler);
                    this.destroySessionIframe();
                    resolve();
                }, 3000);
                return;
            }

            const iframe = document.createElement('iframe');
            iframe.src = this.authOrigin + '/auth/';
            iframe.style.cssText = 'position:fixed;width:0;height:0;border:none;opacity:0;pointer-events:none;';

            const timeout = setTimeout(() => {
                cleanup();
                resolve();
            }, 3000);

            const cleanup = () => {
                clearTimeout(timeout);
                window.removeEventListener('message', handler);
                iframe.remove();
            };

            const handler = (e: MessageEvent) => {
                if (e.origin !== this.authOrigin) return;
                if (e.source !== iframe.contentWindow) return;
                const data = e.data;
                if (!data || typeof data.type !== 'string') return;

                if (data.type === 'privasys:ready') {
                    iframe.contentWindow!.postMessage(
                        { type: 'privasys:clear-session', rpId: this.rpId },
                        this.authOrigin,
                    );
                } else if (data.type === 'privasys:session-cleared') {
                    cleanup();
                    resolve();
                }
            };

            window.addEventListener('message', handler);
            document.body.appendChild(iframe);
        });
    }

    /**
     * Mint a per-audience access token (challenge mode) without rotating
     * the user's primary session. Used to call services that demand a
     * specific `aud` claim — most notably `aud=attestation-server` for
     * the GCP-side verify-quote endpoint.
     *
     * Implementation: relays a `privasys:get-token-for-audience` postMessage
     * to the auth iframe, which performs an OIDC `refresh_token` grant
     * with an explicit `scope=audience:<aud> ...`. The IdP rotates the
     * refresh token (the iframe persists the new one) but the returned
     * access token is audience-bound and never replaces the session token
     * the parent already holds.
     *
     * Requires an active session — call {@link AuthFrame.getSession} first.
     */
    getTokenForAudience(audience: string): Promise<string> {
        return new Promise((resolve, reject) => {
            if (!this.sessionIframe?.contentWindow) {
                reject(new Error('no active session iframe; call getSession() first'));
                return;
            }
            const id = `aud-${Date.now()}-${Math.random().toString(36).slice(2)}`;
            const target = this.sessionIframe.contentWindow;
            const handler = (e: MessageEvent) => {
                if (e.origin !== this.authOrigin) return;
                if (e.source !== target) return;
                const data = e.data;
                if (!data || data.type !== 'privasys:token-for-audience:response' || data.id !== id) return;
                window.removeEventListener('message', handler);
                clearTimeout(timer);
                if (typeof data.error === 'string') reject(new Error(data.error));
                else if (typeof data.accessToken === 'string') resolve(data.accessToken);
                else reject(new Error('malformed response from auth frame'));
            };
            const timer = setTimeout(() => {
                window.removeEventListener('message', handler);
                reject(new Error('timeout minting audience token'));
            }, 15_000);
            window.addEventListener('message', handler);
            target.postMessage(
                { type: 'privasys:get-token-for-audience', id, rpId: this.rpId, audience },
                this.authOrigin,
            );
        });
    }

    /**
     * One-call sealed-session acquisition for this frame's
     * `sessionRelay.appHost` — the API adopters should use instead of
     * hand-rolling resume/approval logic:
     *
     *   1. try the silent voucher resume (`resumeSession`);
     *   2. if there is NO voucher yet, ask the user's wallet to issue one
     *      via a push approval (`requestAppVoucher` — one biometric tap on
     *      the phone, no sign-out, no redirect), then resume again.
     *
     * A `rejected` resume (the enclave's identity or measurement changed)
     * is NOT auto-recovered — it needs a fresh verification ceremony, so it
     * is rethrown for the app to route to sign-in. Other rejections:
     * `no-push` (session not wallet-backed), `timeout` (approval not
     * granted / wallet app too old), `no-session`.
     */
    async ensureAppSession(opts?: {
        /** Set false to disable the push-approval fallback (resume only). */
        pushApproval?: boolean;
        /** Fired when the flow starts waiting on the phone approval. */
        onAwaitingApproval?: () => void;
    }): Promise<SealedSession> {
        const appHost = this.config.sessionRelay?.appHost;
        if (!appHost) {
            throw new Error('AuthFrame: ensureAppSession() requires sessionRelay config');
        }
        try {
            return await this.resumeSession();
        } catch (err) {
            const msg = (err as Error).message ?? '';
            // Only a missing voucher is recoverable with a push approval.
            if ((opts?.pushApproval ?? true) === false || !msg.includes('no-voucher')) {
                throw err;
            }
        }
        // Mount the persistent session iframe (idempotent) so the voucher
        // RPC has a live channel, then request + resume.
        await this.getSession();
        opts?.onAwaitingApproval?.();
        await this.requestAppVoucher(appHost);
        return this.resumeSession();
    }

    /**
     * Ask the user's wallet — via push notification — to voucher an
     * ADDITIONAL enclave host for the current session (incremental
     * multi-app attestation). One biometric approval on the phone mints
     * the EncAuth voucher; afterwards `resumeSession()` (or a per-host
     * frame's `getSealedSession` equivalent) establishes the sealed
     * session silently. No sign-out, no WebAuthn ceremony, no redirect.
     *
     * Resolves once the wallet has issued a NEW voucher for `appHost`.
     * Rejects with:
     *  - `no-session`  — no active session for this rpId;
     *  - `no-push`     — the session has no wallet push token (e.g. a
     *                    social/passkey sign-in) — fall back to a fresh
     *                    wallet sign-in;
     *  - `timeout`     — the user did not approve in time (or the wallet
     *                    app predates voucher-only pushes).
     *
     * Requires an active session — call {@link AuthFrame.getSession} first.
     */
    requestAppVoucher(appHost: string): Promise<void> {
        return new Promise((resolve, reject) => {
            if (!this.sessionIframe?.contentWindow) {
                reject(new Error('no active session iframe; call getSession() first'));
                return;
            }
            const id = `vch-${Date.now()}-${Math.random().toString(36).slice(2)}`;
            const target = this.sessionIframe.contentWindow;
            const handler = (e: MessageEvent) => {
                if (e.origin !== this.authOrigin) return;
                if (e.source !== target) return;
                const data = e.data;
                if (!data || data.type !== 'privasys:voucher-request:response' || data.id !== id) return;
                window.removeEventListener('message', handler);
                clearTimeout(timer);
                if (typeof data.error === 'string') reject(new Error(data.error));
                else resolve();
            };
            // Generous timeout: a human has to pick up their phone. The
            // frame-host runs its own (shorter) poll deadline and reports
            // `timeout` before this fires in the normal case.
            const timer = setTimeout(() => {
                window.removeEventListener('message', handler);
                reject(new Error('timeout'));
            }, 150_000);
            window.addEventListener('message', handler);
            target.postMessage(
                {
                    type: 'privasys:voucher-request',
                    id,
                    rpId: this.rpId,
                    appHost,
                    appName: this.config.appName,
                    clientId: this.config.clientId
                },
                this.authOrigin,
            );
        });
    }

    /**
     * Tear down any active iframes owned by THIS instance only.
     *
     * Important: only iframes that this `AuthFrame` created (the
     * `signIn()` overlay, the `getSession()` renewal iframe, and the
     * sealed session iframe) are removed. We deliberately do NOT do a
     * document-wide `querySelector('iframe[src^=…/auth/]')` cleanup —
     * that would tear down the persistent renewal iframe owned by
     * another `AuthFrame` instance (typically the app-wide
     * `PrivasysAuthProvider`), silently breaking its OIDC refresh
     * timer and surfacing as a delayed "Session expired" the next
     * time the JWT actually times out.
     */
    destroy(): void {
        this.destroySessionIframe();
        this.destroySealedIframe();
    }

    private destroySealedIframe(): void {
        if (this.sealedHandler) {
            window.removeEventListener('message', this.sealedHandler);
            this.sealedHandler = null;
        }
        if (this.sealedIframe) {
            this.sealedIframe.remove();
            this.sealedIframe = null;
        }
        const err = new Error('AuthFrame destroyed');
        for (const [, p] of this.sealedReqs) p.reject(err);
        this.sealedReqs.clear();
        for (const r of this.sealedReadyRejecters) r(err);
        this.sealedReadyResolvers = [];
        this.sealedReadyRejecters = [];
        this.sealedSession = null;
    }

    private destroySessionIframe(): void {
        if (this.sessionHandler) {
            window.removeEventListener('message', this.sessionHandler);
            this.sessionHandler = null;
        }
        if (this.sessionIframe) {
            this.sessionIframe.remove();
            this.sessionIframe = null;
        }
        this.cachedSession = null;
    }
}
