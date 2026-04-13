// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import type { AuthResult, AuthState, AttestationInfo } from './types';
import type { WebAuthnState } from './webauthn';
import { PrivasysAuth } from './client';
import { WebAuthnClient } from './webauthn';
import qrcode from 'qrcode-generator';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Configuration for the built-in auth UI. */
export interface AuthUIConfig {
    /** Management service API base URL (e.g., "https://api.developer.privasys.org"). */
    apiBase: string;
    /** App name or UUID as registered on the platform. */
    appName: string;
    /** Relying party ID. Defaults to `appName` (used as-is). Set this to
     *  the full RP domain like `"my-app.apps.privasys.org"` if different. */
    rpId?: string;
    /** WebSocket URL for the auth broker relay. */
    brokerUrl?: string;
    /** Timeout in milliseconds for the entire flow (default: 120 000). */
    timeout?: number;
    /** Custom element to mount the overlay into (default: document.body). */
    container?: HTMLElement;
    /** Push token from a previous session. When present the UI will offer
     *  to send a push notification instead of showing a QR code. */
    pushToken?: string;
}

/** Resolved result returned by `signIn()`. */
export interface SignInResult {
    /** Opaque session token issued by the enclave. */
    sessionToken: string;
    /** Method used: "wallet" or "passkey". */
    method: 'wallet' | 'passkey';
    /** Attestation info (wallet only). */
    attestation?: AttestationInfo;
    /** Session ID. */
    sessionId: string;
    /** Push token for sending future auth requests (wallet only). */
    pushToken?: string;
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

type UIState =
    | 'idle'
    | 'push-waiting'
    | 'qr-scanning'
    | 'wallet-connected'
    | 'authenticating'
    | 'passkey-requesting'
    | 'passkey-ceremony'
    | 'passkey-verifying'
    | 'success'
    | 'error';

// ---------------------------------------------------------------------------
// Styles (injected into Shadow DOM)
// ---------------------------------------------------------------------------

const MODAL_CSS = /* css */ `
:host {
    all: initial;
    position: fixed;
    inset: 0;
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #111;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

.overlay {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.35);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
}

.modal {
    position: relative;
    width: 100%;
    max-width: 420px;
    margin: 16px;
    background: #fff;
    border-radius: 16px;
    padding: 40px 36px 28px;
    text-align: center;
    box-shadow: 0 24px 64px rgba(0,0,0,0.15), 0 2px 8px rgba(0,0,0,0.08);
    animation: modal-enter 0.2s ease-out;
}
@keyframes modal-enter {
    from { opacity: 0; transform: translateY(12px) scale(0.97); }
    to   { opacity: 1; transform: translateY(0) scale(1); }
}

/* Brand header */
.brand {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    margin-bottom: 28px;
}
.brand-icon {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    overflow: hidden;
    flex-shrink: 0;
}
.brand-icon svg { width: 100%; height: 100%; display: block; }
.brand-title {
    font-size: 18px;
    font-weight: 600;
    line-height: 1.3;
}
.brand-sub {
    font-size: 13px;
    color: rgba(0,0,0,0.45);
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
}

/* Provider buttons */
.btn-provider {
    display: flex;
    align-items: center;
    width: 100%;
    gap: 12px;
    padding: 13px 16px;
    border: 1px solid rgba(0,0,0,0.1);
    border-radius: 10px;
    background: #fff;
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s, box-shadow 0.15s;
    text-align: left;
    font-family: inherit;
    font-size: 14px;
    color: #111;
}
.btn-provider:hover {
    background: rgba(0,0,0,0.03);
    border-color: rgba(0,0,0,0.2);
    box-shadow: 0 1px 4px rgba(0,0,0,0.05);
}
.btn-provider:active { transform: scale(0.995); }
.btn-provider svg {
    width: 22px;
    height: 22px;
    flex-shrink: 0;
    color: rgba(0,0,0,0.45);
}
.btn-provider.wallet svg { color: #059669; }
.btn-label { font-weight: 500; flex: 1; }
.btn-hint {
    font-size: 11px;
    color: rgba(0,0,0,0.45);
    flex-shrink: 0;
}

/* Divider */
.divider {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 16px 0;
    color: rgba(0,0,0,0.35);
    font-size: 12px;
}
.divider::before, .divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(0,0,0,0.1);
}

/* Register link */
.register-link {
    margin-top: 16px;
    font-size: 13px;
    color: rgba(0,0,0,0.45);
}

/* Alternative actions (push-waiting fallbacks) */
.alt-actions {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.link-btn {
    background: none;
    border: none;
    color: #2563eb;
    font-size: inherit;
    font-family: inherit;
    cursor: pointer;
    padding: 0;
}
.link-btn:hover { text-decoration: underline; }

/* QR section */
.qr-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
}
.qr-frame {
    background: #fff;
    border-radius: 12px;
    padding: 16px;
    border: 1px solid rgba(0,0,0,0.1);
    display: inline-flex;
}
.qr-frame svg { width: 200px; height: 200px; }
.scan-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    font-weight: 500;
}
.pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #059669;
    animation: pulse-anim 2s ease-in-out infinite;
}
@keyframes pulse-anim {
    0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(5,150,105,0.4); }
    50%      { opacity: 0.7; box-shadow: 0 0 0 6px rgba(5,150,105,0); }
}
.scan-hint {
    font-size: 13px;
    color: rgba(0,0,0,0.45);
    max-width: 280px;
    line-height: 1.5;
}

/* Progress / spinner */
.progress-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 24px;
    padding: 8px 0 16px;
}
.spinner {
    width: 44px;
    height: 44px;
    border: 3px solid rgba(0,0,0,0.08);
    border-top-color: #059669;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.steps {
    display: flex;
    flex-direction: column;
    gap: 8px;
    text-align: left;
    width: 100%;
    max-width: 280px;
}
.step {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: rgba(0,0,0,0.45);
    transition: color 0.2s;
}
.step.active { color: #111; font-weight: 500; }
.step.done   { color: #059669; }
.step-icon {
    width: 18px;
    text-align: center;
    font-weight: 600;
    flex-shrink: 0;
}

/* Success */
.success-icon { color: #059669; margin-bottom: 12px; }
.success-icon svg { width: 48px; height: 48px; }
.success-title { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
.success-method {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-bottom: 20px;
}
.method-badge {
    font-size: 12px;
    font-weight: 600;
    background: rgba(5,150,105,0.06);
    color: #059669;
    border: 1px solid rgba(5,150,105,0.2);
    padding: 2px 10px;
    border-radius: 999px;
}
.method-detail { font-size: 12px; color: rgba(0,0,0,0.45); }
.session-info {
    text-align: left;
    border: 1px solid rgba(0,0,0,0.06);
    border-radius: 8px;
    overflow: hidden;
}
.session-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    font-size: 13px;
}
.session-row + .session-row { border-top: 1px solid rgba(0,0,0,0.06); }
.session-label {
    font-weight: 500;
    min-width: 56px;
    color: rgba(0,0,0,0.45);
    font-size: 12px;
}
.session-value {
    flex: 1;
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

/* Error */
.error-icon { color: #dc2626; margin-bottom: 12px; }
.error-icon svg { width: 48px; height: 48px; }
.error-title { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
.error-msg {
    font-size: 13px;
    color: rgba(0,0,0,0.45);
    margin-bottom: 20px;
    max-width: 320px;
    margin-left: auto;
    margin-right: auto;
    line-height: 1.5;
}
.btn-retry {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    padding: 13px 16px;
    border: 1px solid rgba(0,0,0,0.1);
    border-radius: 10px;
    background: #fff;
    cursor: pointer;
    font-family: inherit;
    font-size: 14px;
    font-weight: 500;
    color: #111;
    transition: background 0.15s;
}
.btn-retry:hover { background: rgba(0,0,0,0.03); }

/* Footer */
.footer {
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid rgba(0,0,0,0.06);
    font-size: 11px;
    color: rgba(0,0,0,0.35);
}

/* Dark mode */
@media (prefers-color-scheme: dark) {
    :host { color: #f0f0f0; }
    .modal {
        background: #1a1a1a;
        box-shadow: 0 24px 64px rgba(0,0,0,0.4), 0 2px 8px rgba(0,0,0,0.3);
    }
    .btn-provider {
        background: #1a1a1a;
        border-color: rgba(255,255,255,0.1);
        color: #f0f0f0;
    }
    .btn-provider:hover {
        background: rgba(255,255,255,0.05);
        border-color: rgba(255,255,255,0.2);
    }
    .btn-provider svg { color: rgba(255,255,255,0.45); }
    .btn-provider.wallet svg { color: #059669; }
    .brand-sub { color: rgba(255,255,255,0.45); }
    .btn-hint { color: rgba(255,255,255,0.45); }
    .btn-label { color: #f0f0f0; }
    .divider { color: rgba(255,255,255,0.3); }
    .divider::before, .divider::after { background: rgba(255,255,255,0.1); }
    .register-link { color: rgba(255,255,255,0.45); }
    .scan-hint { color: rgba(255,255,255,0.45); }
    .qr-frame { border-color: rgba(255,255,255,0.1); }
    .step { color: rgba(255,255,255,0.45); }
    .step.active { color: #f0f0f0; }
    .spinner { border-color: rgba(255,255,255,0.1); border-top-color: #059669; }
    .session-info { border-color: rgba(255,255,255,0.08); }
    .session-row + .session-row { border-color: rgba(255,255,255,0.08); }
    .session-label { color: rgba(255,255,255,0.45); }
    .method-detail { color: rgba(255,255,255,0.45); }
    .error-msg { color: rgba(255,255,255,0.45); }
    .btn-retry { background: #1a1a1a; border-color: rgba(255,255,255,0.1); color: #f0f0f0; }
    .btn-retry:hover { background: rgba(255,255,255,0.05); }
    .footer { border-color: rgba(255,255,255,0.06); color: rgba(255,255,255,0.3); }
    .overlay { background: rgba(0,0,0,0.55); }

    .brand-title { color: #f0f0f0; }
    .scan-label { color: #f0f0f0; }
    .success-title { color: #f0f0f0; }
    .error-title { color: #f0f0f0; }
}
`;

// ---------------------------------------------------------------------------
// SVG icon templates
// ---------------------------------------------------------------------------

const ICON_LOGO = `<svg viewBox="0 0 500 500"><style>.ld{fill:#fff}@media(prefers-color-scheme:dark){.ld{fill:#2a2a2a}}</style><defs><linearGradient id="pg" y2="1"><stop offset="21%" stop-color="#34E89E"/><stop offset="42%" stop-color="#12B06E"/></linearGradient><linearGradient id="pb" x1="1" y1="1" x2="0" y2="0"><stop offset="21%" stop-color="#00BCF2"/><stop offset="42%" stop-color="#00A0EB"/></linearGradient></defs><path d="M100 0H450L0 450V100A100 100 0 0 1 100 0Z" fill="url(#pg)"/><path d="M500 50V400A100 100 0 0 1 400 500H50L500 50Z" fill="url(#pb)"/><polygon class="ld" points="0,500 50,500 500,50 500,0"/></svg>`;

const ICON_SHIELD = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l7 4v5c0 5.25-3.5 9.74-7 11-3.5-1.26-7-5.75-7-11V6l7-4z"/><path d="M9.5 12l2 2 3.5-4" stroke-width="2"/></svg>`;
const ICON_SHIELD_PLAIN = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l7 4v5c0 5.25-3.5 9.74-7 11-3.5-1.26-7-5.75-7-11V6l7-4z"/></svg>`;
const ICON_PASSKEY = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 11c0-1.1.9-2 2-2s2 .9 2 2-.9 2-2 2-2-.9-2-2z"/><path d="M17.5 15.5c0-1.93-1.57-3.5-3.5-3.5s-3.5 1.57-3.5 3.5"/><rect x="3" y="4" width="18" height="16" rx="3"/></svg>`;
const ICON_CHECK_CIRCLE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-6"/></svg>`;
const ICON_X_CIRCLE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>`;
const ICON_PHONE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="3"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function el(tag: string, attrs?: Record<string, any> | null, ...children: (Node | string | null | false)[]): HTMLElement {
    const e = document.createElement(tag);
    if (attrs != null) {
        for (const [k, v] of Object.entries(attrs)) {
            if (k === 'className') e.className = v as string;
            else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
            else if (k === 'html') e.innerHTML = v as string;
            else if (v === false || v == null) { /* skip */ }
            else if (v === true) e.setAttribute(k, '');
            else e.setAttribute(k, String(v));
        }
    }
    for (const c of children.flat(Infinity) as (Node | string | null | false)[]) {
        if (c == null || c === false) continue;
        e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return e;
}

function renderQRSvg(payload: string): string {
    try {
        const qr = qrcode(0, 'M');
        qr.addData(payload);
        qr.make();
        const count = qr.getModuleCount();
        const cellSize = Math.max(3, Math.floor(200 / count));
        return qr.createSvgTag({ cellSize, margin: 4, scalable: true });
    } catch {
        return `<div style="padding:16px;font-size:11px;word-break:break-all">${payload}</div>`;
    }
}

// ---------------------------------------------------------------------------
// AuthUI
// ---------------------------------------------------------------------------

/**
 * Built-in authentication UI overlay for Privasys enclaves.
 *
 * Shows a centered sign-in modal (similar to Google / Microsoft) with:
 * - **Continue with Privasys Wallet** — QR code + broker relay
 * - **Sign in with passkey** — Browser WebAuthn (Touch ID, Windows Hello)
 *
 * Usage:
 * ```ts
 * const ui = new Privasys.AuthUI({
 *   apiBase: 'https://api.developer.privasys.org',
 *   appName: 'my-app',
 * });
 * const result = await ui.signIn();
 * console.log(result.sessionToken);
 * ```
 *
 * The modal is rendered inside an isolated Shadow DOM so its styles never
 * leak into or conflict with the host page.
 */
export class AuthUI {
    private readonly cfg: Required<Pick<AuthUIConfig, 'apiBase' | 'appName' | 'brokerUrl' | 'timeout'>> & AuthUIConfig;
    private host: HTMLElement | null = null;
    private shadow: ShadowRoot | null = null;
    private resolve: ((r: SignInResult) => void) | null = null;
    private reject: ((e: Error) => void) | null = null;
    private relayClient: PrivasysAuth | null = null;
    private webauthnClient: WebAuthnClient | null = null;
    private state: UIState = 'idle';
    private errorMsg = '';
    private sessionToken = '';
    private sessionId = '';
    private attestation: AttestationInfo | undefined;
    private pushToken: string | undefined;
    private method: 'wallet' | 'passkey' = 'wallet';

    constructor(config: AuthUIConfig) {
        this.cfg = {
            brokerUrl: 'wss://relay.privasys.org/relay',
            timeout: 120_000,
            ...config,
        };
    }

    /** The RP ID used for authentication. */
    get rpId(): string {
        return this.cfg.rpId ?? this.cfg.appName;
    }

    /**
     * Show the authentication modal and wait for the user to sign in.
     * Resolves with the session token or rejects on cancel / error.
     */
    signIn(): Promise<SignInResult> {
        // If already open, close and re-open
        this.close();

        return new Promise<SignInResult>((resolve, reject) => {
            this.resolve = resolve;
            this.reject = reject;
            this.state = 'idle';
            this.errorMsg = '';
            this.sessionToken = '';
            this.sessionId = '';
            this.attestation = undefined;
            this.mount();

            // If returning user (push token available), skip idle and send push immediately
            if (this.cfg.pushToken) {
                this.startPush();
            } else {
                this.render();
            }
        });
    }

    /** Close the modal without completing authentication. */
    close(): void {
        this.cleanup();
        if (this.host) {
            this.host.remove();
            this.host = null;
            this.shadow = null;
        }
    }

    /** Destroy the instance. */
    destroy(): void {
        this.close();
        if (this.reject) {
            this.reject(new Error('AuthUI destroyed'));
            this.resolve = null;
            this.reject = null;
        }
    }

    // ---- mount / render ----

    private mount(): void {
        this.host = document.createElement('div');
        this.host.setAttribute('data-privasys-auth', '');
        this.shadow = this.host.attachShadow({ mode: 'closed' });

        const style = document.createElement('style');
        style.textContent = MODAL_CSS;
        this.shadow.appendChild(style);

        const container = this.cfg.container ?? document.body;
        container.appendChild(this.host);
    }

    private render(): void {
        if (!this.shadow) return;
        // Remove old content (keep style)
        const style = this.shadow.querySelector('style')!;
        this.shadow.innerHTML = '';
        this.shadow.appendChild(style);

        // Overlay
        const overlay = el('div', { className: 'overlay', onClick: () => this.handleCancel() });
        this.shadow.appendChild(overlay);

        // Modal (stop click propagation so overlay click doesn't fire)
        let modal: HTMLElement;

        switch (this.state) {
            case 'idle':
                modal = this.renderIdle();
                break;
            case 'push-waiting':
                modal = this.renderPushWaiting();
                break;
            case 'qr-scanning':
                modal = this.renderQR();
                break;
            case 'wallet-connected':
            case 'authenticating':
                modal = this.renderWalletProgress();
                break;
            case 'passkey-requesting':
            case 'passkey-ceremony':
            case 'passkey-verifying':
                modal = this.renderPasskeyProgress();
                break;
            case 'success':
                modal = this.renderSuccess();
                break;
            case 'error':
                modal = this.renderError();
                break;
            default:
                modal = this.renderIdle();
        }

        modal.addEventListener('click', (e) => e.stopPropagation());
        this.shadow.appendChild(modal);
    }

    // ---- state-specific views ----

    private renderIdle(): HTMLElement {
        const hasWebAuthn = WebAuthnClient.isSupported();
        const hasPush = !!this.cfg.pushToken;

        return el('div', { className: 'modal' },
            this.brandHeader(),
            // Push-first: if we have a push token from a previous session
            hasPush ? el('button', { className: 'btn-provider wallet', onClick: () => this.startPush() },
                el('span', { html: ICON_PHONE }),
                el('span', { className: 'btn-label' }, 'Connect with Privasys Wallet'),
                el('span', { className: 'btn-hint' }, 'Notification to your phone'),
            ) : null,
            // QR wallet button — primary when no push token, secondary otherwise
            el('button', { className: 'btn-provider wallet', onClick: () => this.startWallet() },
                el('span', { html: ICON_SHIELD_PLAIN }),
                el('span', { className: 'btn-label' }, hasPush ? 'Scan QR code instead' : 'Continue with Privasys Wallet'),
                el('span', { className: 'btn-hint' }, hasPush ? 'New device' : 'Attestation verified'),
            ),
            // Divider + passkey
            hasWebAuthn ? el('div', { className: 'divider' }, el('span', null, 'or')) : null,
            hasWebAuthn ? el('button', { className: 'btn-provider', onClick: () => this.startPasskey('authenticate') },
                el('span', { html: ICON_PASSKEY }),
                el('span', { className: 'btn-label' }, 'Sign in with passkey'),
                el('span', { className: 'btn-hint' }, 'Windows Hello, Touch ID, Face ID'),
            ) : null,
            // Register link
            hasWebAuthn ? el('div', { className: 'register-link' },
                'No passkey yet? ',
                el('button', { className: 'link-btn', onClick: () => this.startPasskey('register') }, 'Register one'),
            ) : null,
            // Footer
            el('div', { className: 'footer' }, 'Secured by end-to-end encryption inside a hardware enclave'),
        );
    }

    private renderQR(): HTMLElement {
        const client = this.getRelayClient();
        const { payload } = client.createQR(this.sessionId);

        return el('div', { className: 'modal' },
            this.brandHeader(),
            el('div', { className: 'qr-section' },
                el('div', { className: 'qr-frame', html: renderQRSvg(payload) }),
                el('div', { className: 'scan-label' },
                    el('span', { className: 'pulse' }),
                    'Scan with Privasys Wallet',
                ),
                el('p', { className: 'scan-hint' },
                    'Open the wallet app on your phone and scan this QR code to authenticate.',
                ),
            ),
            el('div', { className: 'footer' },
                el('button', { className: 'link-btn', onClick: () => this.handleCancel() }, 'Cancel'),
            ),
        );
    }

    private renderPushWaiting(): HTMLElement {
        const hasWebAuthn = WebAuthnClient.isSupported();
        return el('div', { className: 'modal' },
            this.brandHeader(),
            el('div', { className: 'progress-section' },
                el('div', { className: 'spinner' }),
                el('div', { className: 'steps' },
                    el('div', { className: 'step done' },
                        el('span', { className: 'step-icon' }, '\u2713'), 'Notification sent',
                    ),
                    el('div', { className: 'step active' },
                        el('span', { className: 'step-icon' }, '\u2022'), 'Waiting for your wallet\u2026',
                    ),
                    el('div', { className: 'step' },
                        el('span', { className: 'step-icon' }, '\u2022'), 'Biometric authentication',
                    ),
                ),
                el('p', { className: 'scan-hint' },
                    'Check your phone \u2014 tap the notification to approve this connection.',
                ),
            ),
            el('div', { className: 'divider' }, el('span', null, 'or')),
            el('div', { className: 'alt-actions' },
                el('button', { className: 'btn-provider wallet', onClick: () => { this.cleanup(); this.startWallet(); } },
                    el('span', { html: ICON_SHIELD_PLAIN }),
                    el('span', { className: 'btn-label' }, 'Scan QR code instead'),
                    el('span', { className: 'btn-hint' }, 'New device'),
                ),
                hasWebAuthn ? el('button', { className: 'btn-provider', onClick: () => { this.cleanup(); this.startPasskey('authenticate'); } },
                    el('span', { html: ICON_PASSKEY }),
                    el('span', { className: 'btn-label' }, 'Sign in with passkey'),
                    el('span', { className: 'btn-hint' }, 'Windows Hello, Touch ID, Face ID'),
                ) : null,
            ),
            el('div', { className: 'footer' },
                el('button', { className: 'link-btn', onClick: () => this.handleCancel() }, 'Cancel'),
            ),
        );
    }

    private renderWalletProgress(): HTMLElement {
        const isAuth = this.state === 'authenticating';
        const viaPush = !!this.cfg.pushToken && this.state !== 'qr-scanning';
        const firstStep = viaPush ? 'Notification sent' : 'QR code scanned';
        return el('div', { className: 'modal' },
            this.brandHeader(),
            el('div', { className: 'progress-section' },
                el('div', { className: 'spinner' }),
                el('div', { className: 'steps' },
                    el('div', { className: 'step done' },
                        el('span', { className: 'step-icon' }, '\u2713'), firstStep,
                    ),
                    el('div', { className: `step ${isAuth ? 'done' : 'active'}` },
                        el('span', { className: 'step-icon' }, isAuth ? '\u2713' : '\u2022'), 'Verifying enclave attestation',
                    ),
                    el('div', { className: `step ${isAuth ? 'active' : ''}` },
                        el('span', { className: 'step-icon' }, '\u2022'), 'FIDO2 biometric ceremony',
                    ),
                ),
            ),
            el('div', { className: 'footer' },
                el('button', { className: 'link-btn', onClick: () => this.handleCancel() }, 'Cancel'),
            ),
        );
    }

    private renderPasskeyProgress(): HTMLElement {
        const isRegister = this.method === 'passkey'; // both use passkey method
        const phase = this.state;
        return el('div', { className: 'modal' },
            el('div', { className: 'brand' },
                el('div', { className: 'brand-icon', html: ICON_PASSKEY }),
                el('div', null,
                    el('div', { className: 'brand-title' },
                        phase === 'passkey-requesting' ? 'Preparing\u2026' : 'Verify your identity',
                    ),
                    el('div', { className: 'brand-sub' }, this.rpId),
                ),
            ),
            el('div', { className: 'progress-section' },
                el('div', { className: 'spinner' }),
                el('div', { className: 'steps' },
                    el('div', { className: `step ${phase !== 'passkey-requesting' ? 'done' : 'active'}` },
                        el('span', { className: 'step-icon' }, phase !== 'passkey-requesting' ? '\u2713' : '\u2022'),
                        'Requesting options from enclave',
                    ),
                    el('div', { className: `step ${phase === 'passkey-ceremony' ? 'active' : phase === 'passkey-verifying' ? 'done' : ''}` },
                        el('span', { className: 'step-icon' }, phase === 'passkey-verifying' ? '\u2713' : '\u2022'),
                        'Complete biometric prompt',
                    ),
                    el('div', { className: `step ${phase === 'passkey-verifying' ? 'active' : ''}` },
                        el('span', { className: 'step-icon' }, '\u2022'),
                        'Enclave verification',
                    ),
                ),
            ),
            el('div', { className: 'footer' },
                el('button', { className: 'link-btn', onClick: () => this.handleCancel() }, 'Cancel'),
            ),
        );
    }

    private renderSuccess(): HTMLElement {
        const masked = this.sessionToken
            ? '\u25CF'.repeat(8) + this.sessionToken.slice(-6)
            : '\u2014';

        const methodLabel = this.method === 'wallet' ? 'Privasys Wallet' : 'Passkey';
        const methodDetail = this.method === 'wallet' ? 'Attestation verified' : 'This device';

        return el('div', { className: 'modal' },
            el('div', { className: 'success-icon', html: ICON_CHECK_CIRCLE }),
            el('div', { className: 'success-title' }, 'Authenticated'),
            el('div', { className: 'success-method' },
                el('span', { className: 'method-badge' }, methodLabel),
                el('span', { className: 'method-detail' }, methodDetail),
            ),
            el('div', { className: 'session-info' },
                el('div', { className: 'session-row' },
                    el('span', { className: 'session-label' }, 'Session'),
                    el('span', { className: 'session-value' }, masked),
                ),
                el('div', { className: 'session-row' },
                    el('span', { className: 'session-label' }, 'App'),
                    el('span', { className: 'session-value' }, this.rpId),
                ),
            ),
            el('div', { className: 'footer' },
                'Your session is ready. This dialog will close automatically.',
            ),
        );
    }

    private renderError(): HTMLElement {
        return el('div', { className: 'modal' },
            el('div', { className: 'error-icon', html: ICON_X_CIRCLE }),
            el('div', { className: 'error-title' }, 'Authentication failed'),
            el('div', { className: 'error-msg' }, this.errorMsg || 'An unknown error occurred.'),
            el('button', { className: 'btn-retry', onClick: () => {
                this.errorMsg = '';
                if (this.cfg.pushToken) {
                    this.startPush();
                } else {
                    this.state = 'idle';
                    this.render();
                }
            } },
                'Try again',
            ),
            el('div', { className: 'footer' },
                el('button', { className: 'link-btn', onClick: () => this.handleCancel() }, 'Cancel'),
            ),
        );
    }

    private brandHeader(): HTMLElement {
        return el('div', { className: 'brand' },
            el('div', { className: 'brand-icon', html: ICON_LOGO }),
            el('div', null,
                el('div', { className: 'brand-title' }, `Sign in to ${this.cfg.appName}`),
                el('div', { className: 'brand-sub' }, this.rpId),
            ),
        );
    }

    // ---- flows ----

    private startPush(): void {
        this.method = 'wallet';
        const client = this.getRelayClient();
        this.state = 'push-waiting';
        this.render();

        client.notifyAndWait(this.cfg.pushToken!).then(
            (result) => {
                this.sessionToken = result.sessionToken;
                this.attestation = result.attestation;
                this.sessionId = result.sessionId;
                this.pushToken = result.pushToken;
                this.complete();
            },
            (err) => {
                this.state = 'error';
                this.errorMsg = err?.message ?? 'Push authentication failed';
                this.render();
            },
        );
    }

    private startWallet(): void {
        this.method = 'wallet';
        const client = this.getRelayClient();
        const { sessionId } = client.createQR();
        this.sessionId = sessionId;
        this.state = 'qr-scanning';
        this.render();

        client.waitForResult(sessionId).then(
            (result) => {
                this.sessionToken = result.sessionToken;
                this.attestation = result.attestation;
                this.sessionId = result.sessionId;
                this.pushToken = result.pushToken;
                this.complete();
            },
            (err) => {
                this.state = 'error';
                this.errorMsg = err?.message ?? 'Wallet authentication failed';
                this.render();
            },
        );
    }

    private async startPasskey(op: 'register' | 'authenticate'): Promise<void> {
        this.method = 'passkey';
        this.state = 'passkey-requesting';
        this.render();

        const client = this.getWebAuthnClient();

        try {
            const result = op === 'register'
                ? await client.register(globalThis.location?.hostname ?? 'user')
                : await client.authenticate();
            this.sessionToken = result.sessionToken;
            this.sessionId = result.sessionId;
            this.complete();
        } catch (err: any) {
            this.state = 'error';
            this.errorMsg = err?.message ?? 'Passkey authentication failed';
            this.render();
        }
    }

    private complete(): void {
        this.state = 'success';
        this.render();

        // Auto-close after brief success display
        setTimeout(() => {
            const result: SignInResult = {
                sessionToken: this.sessionToken,
                method: this.method,
                attestation: this.attestation,
                sessionId: this.sessionId,
                pushToken: this.pushToken,
            };
            this.close();
            this.resolve?.(result);
            this.resolve = null;
            this.reject = null;
        }, 1200);
    }

    private handleCancel(): void {
        this.cleanup();
        this.close();
        this.reject?.(new Error('Authentication cancelled'));
        this.resolve = null;
        this.reject = null;
    }

    private cleanup(): void {
        if (this.relayClient) {
            this.relayClient.destroy();
            this.relayClient = null;
        }
    }

    // ---- client accessors ----

    private getRelayClient(): PrivasysAuth {
        if (!this.relayClient) {
            this.relayClient = new PrivasysAuth({
                rpId: this.rpId,
                brokerUrl: this.cfg.brokerUrl,
                timeout: this.cfg.timeout,
            }, {
                onStateChange: (s: AuthState) => {
                    const map: Record<string, UIState> = {
                        'waiting-for-scan': 'qr-scanning',
                        'wallet-connected': 'wallet-connected',
                        'authenticating': 'authenticating',
                    };
                    if (map[s]) {
                        // Don't override push-waiting with qr-scanning
                        if (this.state === 'push-waiting' && s === 'waiting-for-scan') return;
                        this.state = map[s];
                        this.render();
                    }
                },
            });
        }
        return this.relayClient;
    }

    private getWebAuthnClient(): WebAuthnClient {
        if (!this.webauthnClient) {
            this.webauthnClient = new WebAuthnClient({
                apiBase: this.cfg.apiBase,
                appName: this.cfg.appName,
            }, {
                onStateChange: (s: WebAuthnState) => {
                    const map: Record<string, UIState> = {
                        'requesting-options': 'passkey-requesting',
                        'ceremony': 'passkey-ceremony',
                        'verifying': 'passkey-verifying',
                    };
                    if (map[s]) {
                        this.state = map[s];
                        this.render();
                    }
                },
            });
        }
        return this.webauthnClient;
    }
}
