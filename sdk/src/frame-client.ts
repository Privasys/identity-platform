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
 * | `offline_access` | Issues a refresh token (no attributes)                  |
 */
export type PrivasysScope = 'openid' | 'email' | 'profile' | 'phone' | 'offline_access';

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
}

export interface SignInResult {
    sessionToken: string;
    method: 'wallet' | 'passkey';
    attestation?: Record<string, unknown>;
    sessionId: string;
    pushToken?: string;
    /** JWT access_token from the IdP (present when clientId was set in config). */
    accessToken?: string;
}

// ---------------------------------------------------------------------------
// AuthFrame
// ---------------------------------------------------------------------------

export class AuthFrame {
    private readonly authOrigin: string;
    private readonly config: Omit<AuthFrameConfig, 'authOrigin'>;
    private sessionIframe: HTMLIFrameElement | null = null;
    private sessionHandler: ((e: MessageEvent) => void) | null = null;
    private _onSessionExpired?: (rpId: string) => void;
    private _onSessionRenewed?: (rpId: string, accessToken?: string) => void;

    constructor(config: AuthFrameConfig) {
        const { authOrigin, ...rest } = config;
        this.authOrigin = authOrigin ?? 'https://privasys.id';
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
     * Open the authentication modal (inside a privasys.id iframe) and
     * wait for the user to complete the ceremony.
     */
    signIn(): Promise<SignInResult> {
        return new Promise<SignInResult>((resolve, reject) => {
            const iframe = document.createElement('iframe');
            iframe.src = this.authOrigin + '/auth/';
            iframe.style.cssText =
                'position:fixed;inset:0;width:100%;height:100%;' +
                'z-index:999999;border:none;background:#fff;';
            iframe.allow =
                'publickey-credentials-get *; publickey-credentials-create *';

            const cleanup = () => {
                window.removeEventListener('message', handler);
                iframe.remove();
            };

            const handler = (e: MessageEvent) => {
                if (e.origin !== this.authOrigin) return;
                const data = e.data;
                if (!data || typeof data.type !== 'string') return;

                switch (data.type) {
                    case 'privasys:ready':
                        iframe.contentWindow!.postMessage(
                            { type: 'privasys:init', config: this.config },
                            this.authOrigin,
                        );
                        break;

                    case 'privasys:result':
                        cleanup();
                        resolve(data.result as SignInResult);
                        break;

                    case 'privasys:cancel':
                        cleanup();
                        reject(new Error('Authentication cancelled'));
                        break;

                    case 'privasys:error':
                        cleanup();
                        reject(new Error(data.error || 'Authentication failed'));
                        break;
                }
            };

            window.addEventListener('message', handler);
            document.body.appendChild(iframe);
        });
    }

    /**
     * Check whether privasys.id already has a session for this RP.
     * Uses a hidden iframe to query localStorage on the auth origin.
     * The iframe is kept alive so the frame-host can run renewal timers.
     */
    getSession(): Promise<{ token: string; rpId: string; authenticatedAt: number } | null> {
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
                    } else {
                        // No session — clean up
                        window.removeEventListener('message', handler);
                        iframe.remove();
                    }

                    resolve(data.session || null);
                } else if (data.type === 'privasys:session-renewed') {
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
                const handler = (e: MessageEvent) => {
                    if (e.origin !== this.authOrigin) return;
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

    /** Tear down any active iframes. */
    destroy(): void {
        this.destroySessionIframe();
        const existing = document.querySelector(
            `iframe[src^="${this.authOrigin}/auth/"]`,
        );
        if (existing) existing.remove();
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
    }
}
