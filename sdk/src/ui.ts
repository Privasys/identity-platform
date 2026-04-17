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
    /** Pre-assigned session ID (OIDC mode). When set, the QR code and
     *  FIDO2 requests use this ID so the IdP can link them back to the
     *  OIDC authorize session. */
    sessionId?: string;
    /** Attribute keys the relying party needs from the wallet (e.g. ["email", "name"]). */
    requestedAttributes?: string[];
    /** Direct FIDO2 endpoint base URL (OIDC mode). When set, the WebAuthn
     *  client calls `${fido2Base}/${action}` instead of the management
     *  service proxy URL. */
    fido2Base?: string;
    /** Available social identity providers (OIDC mode). Each entry is a
     *  provider name like "github", "google", "microsoft", "linkedin". */
    socialProviders?: string[];
    /** Callback when the user wants to start social auth. The UI calls
     *  this with the provider name; the host opens a popup. */
    onSocialAuth?: (provider: string) => Promise<void>;
    /** URL to the app's privacy policy. Shown to the user when sharing attributes. */
    privacyPolicyUrl?: string;
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
    /** Profile attributes from the wallet (keyed by OIDC claim name). */
    attributes?: Record<string, string>;
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
@import url('https://rsms.me/inter/inter.css');
:host {
    all: initial;
    position: fixed;
    inset: 0;
    z-index: 2147483647;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #0F172A;
    background: #fff;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    overflow-y: auto;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

/* Close button — top right */
.btn-close {
    position: absolute;
    top: 24px;
    right: 24px;
    z-index: 10;
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: none;
    border-radius: 50%;
    background: transparent;
    cursor: pointer;
    color: #94A3B8;
    transition: background 0.15s, color 0.15s;
}
.btn-close:hover { background: #F1F5F9; color: #64748B; }
.btn-close svg { width: 20px; height: 20px; }

/* Back button — top of auth panel */
.btn-back {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: none;
    background: transparent;
    cursor: pointer;
    font-family: inherit;
    font-size: 13px;
    color: #64748B;
    padding: 6px 10px 6px 4px;
    border-radius: 8px;
    margin-bottom: 24px;
    transition: background 0.15s, color 0.15s;
    align-self: flex-start;
}
.btn-back:hover { background: #F1F5F9; color: #0F172A; }
.btn-back svg { width: 16px; height: 16px; }

/* Full-screen two-column layout */
.page {
    display: grid;
    grid-template-columns: 1fr 1fr;
    grid-template-rows: 1fr auto;
    width: 100%;
    min-height: 100vh;
    animation: page-enter 0.25s ease-out;
}
@keyframes page-enter {
    from { opacity: 0; }
    to   { opacity: 1; }
}

/* Left: brand panel */
.brand-panel {
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 64px 48px 64px 64px;
    max-width: 560px;
    margin-left: auto;
}
.brand-panel-header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 32px;
}
.brand-panel-logo {
    width: 44px;
    height: 44px;
    flex-shrink: 0;
}
.brand-panel-logo svg { width: 100%; height: 100%; display: block; }
.brand-panel-name {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: #0F172A;
}
.brand-panel-desc {
    font-size: 17px;
    color: #64748B;
    line-height: 1.6;
    max-width: 400px;
}

/* Right: auth panel */
.auth-panel {
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 64px 64px 64px 48px;
    max-width: 460px;
}
.auth-panel-heading {
    font-size: 20px;
    font-weight: 600;
    color: #0F172A;
    letter-spacing: -0.01em;
    margin-bottom: 28px;
}
/* Center content in auth panel for non-idle states */
.auth-panel--centered {
    align-items: center;
    text-align: center;
}

/* Mobile: single column, compact brand header */
@media (max-width: 768px) {
    .page {
        grid-template-columns: 1fr;
        grid-template-rows: auto 1fr auto;
        min-height: 100vh;
    }
    .brand-panel {
        padding: 20px 24px;
        padding-right: 56px;
        flex-direction: row;
        align-items: center;
        max-width: none;
        margin: 0;
    }
    .brand-panel-header { margin-bottom: 0; }
    .brand-panel-logo { width: 28px; height: 28px; }
    .brand-panel-name { font-size: 16px; }
    .brand-panel-desc { display: none; }
    .auth-panel {
        padding: 0 24px 32px;
        max-width: 420px;
        margin: 0 auto;
        justify-content: center;
    }
    .auth-panel--centered { margin: 0 auto; }
    .btn-close { top: 14px; right: 16px; width: 36px; height: 36px; }
    .btn-hint { display: none; }
    .footer { padding: 16px 24px; }
}

/* Provider buttons */
.btn-provider + .btn-provider { margin-top: 10px; }
.btn-provider {
    display: flex;
    align-items: center;
    width: 100%;
    gap: 12px;
    padding: 14px 16px;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    background: #fff;
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s, box-shadow 0.15s, transform 0.1s;
    text-align: left;
    font-family: inherit;
    font-size: 14px;
    color: #0F172A;
}
.btn-provider:hover {
    background: #F8FAFC;
    border-color: #CBD5E1;
    box-shadow: 0 1px 3px rgba(15,23,42,0.04);
}
.btn-provider:active { transform: scale(0.98); }
.btn-provider > span:not(.btn-label):not(.btn-hint) {
    display: flex;
    align-items: center;
    flex-shrink: 0;
}
.btn-provider svg {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    color: #64748B;
}
.btn-provider.primary {
    background: #0F172A;
    border-color: #0F172A;
    color: #fff;
    padding: 15px 18px;
}
.btn-provider.primary:hover {
    background: #1E293B;
    border-color: #1E293B;
    box-shadow: 0 2px 8px rgba(15,23,42,0.15);
}
.btn-provider.primary svg { color: #fff; }
.btn-provider.primary .btn-hint { color: rgba(255,255,255,0.6); }
.btn-label { font-weight: 500; flex: 1; }
.btn-hint {
    font-size: 11px;
    color: #94A3B8;
    flex-shrink: 0;
}

/* Divider */
.divider {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 20px 0 16px;
    color: #94A3B8;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    width: 100%;
}
.divider::before, .divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: #E2E8F0;
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
    color: #64748B;
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
    border-top-color: #0F172A;
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
    color: #94A3B8;
    transition: color 0.2s;
}
.step.active { color: #0F172A; font-weight: 500; }
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
.method-detail { font-size: 12px; color: #64748B; }
.session-info {
    text-align: left;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    overflow: hidden;
    width: 100%;
}
.session-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    font-size: 13px;
}
.session-row + .session-row { border-top: 1px solid #E2E8F0; }
.session-label {
    font-weight: 500;
    min-width: 56px;
    color: #64748B;
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
    color: #64748B;
    margin-bottom: 20px;
    max-width: 320px;
    line-height: 1.5;
}
.btn-retry {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    padding: 13px 16px;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
    background: #fff;
    cursor: pointer;
    font-family: inherit;
    font-size: 14px;
    font-weight: 500;
    color: #0F172A;
    transition: background 0.15s;
}
.btn-retry:hover { background: #F8FAFC; }

/* Footer */
.footer {
    grid-column: 1 / -1;
    padding: 16px 64px;
    border-top: 1px solid #E2E8F0;
    font-size: 11px;
    color: #94A3B8;
    text-align: center;
}

/* Dark mode */
@media (prefers-color-scheme: dark) {
    :host { color: #E2E8F0; background: #0F172A; }
    .btn-close { color: #64748B; }
    .btn-close:hover { background: rgba(255,255,255,0.06); color: #94A3B8; }
    .btn-back { color: #64748B; }
    .btn-back:hover { background: rgba(255,255,255,0.06); color: #E2E8F0; }
    .brand-panel-name { color: #F1F5F9; }
    .brand-panel-desc { color: #64748B; }
    .auth-panel-heading { color: #F1F5F9; }
    .btn-provider {
        background: rgba(255,255,255,0.04);
        border-color: rgba(255,255,255,0.1);
        color: #E2E8F0;
    }
    .btn-provider:hover {
        background: rgba(255,255,255,0.07);
        border-color: rgba(255,255,255,0.18);
    }
    .btn-provider svg { color: #94A3B8; }
    .btn-provider.primary {
        background: #F1F5F9;
        border-color: #F1F5F9;
        color: #0F172A;
    }
    .btn-provider.primary:hover {
        background: #E2E8F0;
        border-color: #E2E8F0;
    }
    .btn-provider.primary svg { color: #0F172A; }
    .btn-provider.primary .btn-hint { color: rgba(15,23,42,0.5); }
    .btn-hint { color: #64748B; }
    .btn-label { color: #E2E8F0; }
    .divider { color: #475569; }
    .divider::before, .divider::after { background: rgba(255,255,255,0.08); }
    .scan-hint { color: #64748B; }
    .qr-frame { border-color: rgba(255,255,255,0.1); background: #1E293B; }
    .step { color: #64748B; }
    .step.active { color: #E2E8F0; }
    .spinner { border-color: rgba(255,255,255,0.08); border-top-color: #F1F5F9; }
    .session-info { border-color: rgba(255,255,255,0.08); }
    .session-row + .session-row { border-color: rgba(255,255,255,0.08); }
    .session-label { color: #64748B; }
    .method-detail { color: #64748B; }
    .error-msg { color: #64748B; }
    .btn-retry { background: rgba(255,255,255,0.04); border-color: rgba(255,255,255,0.1); color: #E2E8F0; }
    .btn-retry:hover { background: rgba(255,255,255,0.07); }
    .footer { border-color: rgba(255,255,255,0.06); color: #475569; }
    .footer .link-btn { color: #64748B; }
    .scan-label { color: #E2E8F0; }
    .success-title { color: #E2E8F0; }
    .error-title { color: #E2E8F0; }
}
`;

// ---------------------------------------------------------------------------
// SVG icon templates
// ---------------------------------------------------------------------------

const ICON_LOGO = `<svg viewBox="0 0 500 500"><style>.ld{fill:#fff}@media(prefers-color-scheme:dark){.ld{fill:#2a2a2a}}</style><defs><linearGradient id="pg" y2="1"><stop offset="21%" stop-color="#34E89E"/><stop offset="42%" stop-color="#12B06E"/></linearGradient><linearGradient id="pb" x1="1" y1="1" x2="0" y2="0"><stop offset="21%" stop-color="#00BCF2"/><stop offset="42%" stop-color="#00A0EB"/></linearGradient></defs><path d="M100 0H450L0 450V100A100 100 0 0 1 100 0Z" fill="url(#pg)"/><path d="M500 50V400A100 100 0 0 1 400 500H50L500 50Z" fill="url(#pb)"/><polygon class="ld" points="0,500 50,500 500,50 500,0"/></svg>`;
const ICON_PASSKEY = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="10.5" cy="7.5" r="3"/><path d="M10.5 13c-3.3 0-6 2-6 4.5V19h12v-1.5c0-1-.4-2-1-2.7"/><line x1="18" y1="12" x2="18" y2="18"/><line x1="15" y1="15" x2="21" y2="15"/></svg>`;
const ICON_CHECK_CIRCLE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-6"/></svg>`;
const ICON_X_CIRCLE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>`;
const ICON_PHONE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="3"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>`;
// Social provider icons (brand colors, viewBox 24x24)
const ICON_GITHUB = `<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.167 6.839 9.49.5.092.682-.217.682-.482 0-.237-.009-.866-.013-1.7-2.782.604-3.369-1.341-3.369-1.341-.454-1.155-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.337-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836a9.59 9.59 0 012.504.337c1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z"/></svg>`;
const ICON_GOOGLE = `<svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18A10.96 10.96 0 001 12c0 1.77.42 3.45 1.18 4.93l3.66-2.84z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>`;
const ICON_MICROSOFT = `<svg viewBox="0 0 24 24"><rect fill="#F25022" x="2" y="2" width="9.5" height="9.5"/><rect fill="#7FBA00" x="12.5" y="2" width="9.5" height="9.5"/><rect fill="#00A4EF" x="2" y="12.5" width="9.5" height="9.5"/><rect fill="#FFB900" x="12.5" y="12.5" width="9.5" height="9.5"/></svg>`;
const ICON_LINKEDIN = `<svg viewBox="0 0 24 24"><path fill="#0A66C2" d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>`;
const ICON_CLOSE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
const ICON_SHIELD = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`;
const ICON_LOCK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`;
const ICON_FINGERPRINT = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 018 4"/><path d="M5 19.5C5.5 18 6 15 6 12c0-3.3 2.7-6 6-6 1.8 0 3.4.8 4.5 2"/><path d="M12 10a2 2 0 00-2 2c0 4.4-1.2 8-2.5 10"/><path d="M8.5 22c0-3 .5-5.5 1-8"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.5 19.5c0-1.5.5-4 .5-7.5 0-1.7-.8-3.2-2-4.3"/><path d="M22 16.92c-.3-.6-.5-1.3-.5-2.92 0-2.5-1.2-4.8-3-6.3"/></svg>`;
const ICON_ARROW_LEFT = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>`;

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
 * - **Continue with Privasys ID** — QR code + broker relay
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
    private attributes: Record<string, string> | undefined;
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
            this.attributes = undefined;
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

        const displayName = this.cfg.appName
            .replace(/[-_]/g, ' ')
            .replace(/\b\w/g, c => c.toUpperCase());
        const isIdle = this.state === 'idle';

        // Dynamic brand description based on state
        let brandDesc: string;
        switch (this.state) {
            case 'qr-scanning':
                brandDesc = 'Open Privasys Wallet on your phone and scan the QR code displayed on the right to authenticate.';
                break;
            case 'push-waiting':
                brandDesc = 'Check your phone \u2014 tap the notification from Privasys ID to approve this sign-in.';
                break;
            case 'wallet-connected':
            case 'authenticating':
                brandDesc = 'Verifying your identity\u2026 This will only take a moment.';
                break;
            case 'passkey-requesting':
            case 'passkey-ceremony':
            case 'passkey-verifying':
                brandDesc = 'Complete the biometric prompt on your device to verify your identity.';
                break;
            case 'success':
                brandDesc = 'You\u2019ve been authenticated successfully.';
                break;
            case 'error':
                brandDesc = 'Something went wrong. You can try again or choose a different method.';
                break;
            default:
                brandDesc = `${displayName} needs to verify your identity. Please choose one of the authentication options.`;
        }

        // Get auth panel content based on state
        let content: HTMLElement;
        switch (this.state) {
            case 'push-waiting':
                content = this.renderPushWaiting();
                break;
            case 'qr-scanning':
                content = this.renderQR();
                break;
            case 'wallet-connected':
            case 'authenticating':
                content = this.renderWalletProgress();
                break;
            case 'passkey-requesting':
            case 'passkey-ceremony':
            case 'passkey-verifying':
                content = this.renderPasskeyProgress();
                break;
            case 'success':
                content = this.renderSuccess();
                break;
            case 'error':
                content = this.renderError();
                break;
            default:
                content = this.renderIdle();
        }

        const page = el('div', { className: 'page' },
            // Close button
            el('button', { className: 'btn-close', html: ICON_CLOSE, onClick: () => this.handleCancel() }),
            // Left: brand panel
            el('div', { className: 'brand-panel' },
                el('div', { className: 'brand-panel-header' },
                    el('div', { className: 'brand-panel-logo', html: ICON_LOGO }),
                    el('div', { className: 'brand-panel-name' }, 'Privasys'),
                ),
                el('p', { className: 'brand-panel-desc' }, brandDesc),
            ),
            // Right: auth panel
            el('div', { className: `auth-panel${isIdle ? '' : ' auth-panel--centered'}` },
                !isIdle ? el('button', { className: 'btn-back', onClick: () => this.goBack() },
                    el('span', { html: ICON_ARROW_LEFT }),
                    'Back',
                ) : null,
                content,
            ),
            // Footer spans both columns
            el('div', { className: 'footer' },
                'By continuing, you agree to the ',
                el('a', { href: 'https://privasys.org/legal/terms', target: '_blank', className: 'link-btn', style: 'font-size:inherit' }, 'Terms of Service'),
                ' and ',
                el('a', { href: 'https://privasys.org/legal/privacy', target: '_blank', className: 'link-btn', style: 'font-size:inherit' }, 'Privacy Policy'),
                '.',
            ),
        );

        this.shadow.appendChild(page);
    }

    /** Go back to idle state, cancelling any in-progress flow. */
    private goBack(): void {
        this.cleanup();
        this.state = 'idle';
        this.errorMsg = '';
        this.render();
    }

    // ---- state-specific views ----

    private renderIdle(): HTMLElement {
        const hasWebAuthn = WebAuthnClient.isSupported();
        const hasPush = !!this.cfg.pushToken;
        const socialProviders = this.cfg.socialProviders ?? [];
        const displayName = this.cfg.appName
            .replace(/[-_]/g, ' ')
            .replace(/\b\w/g, c => c.toUpperCase());

        const buttons: (HTMLElement | null | false)[] = [];

        // Push-first: returning user with push token
        if (hasPush) {
            buttons.push(
                el('button', { className: 'btn-provider primary', onClick: () => this.startPush() },
                    el('span', { html: ICON_PHONE }),
                    el('span', { className: 'btn-label' }, 'Sign in with Privasys ID'),
                    el('span', { className: 'btn-hint' }, 'Notification'),
                ),
            );
        }

        // Primary wallet/QR button — Privasys logo in the button
        buttons.push(
            el('button', { className: `btn-provider ${hasPush ? '' : 'primary'}`, onClick: () => this.startWallet() },
                el('span', { html: ICON_LOGO }),
                el('span', { className: 'btn-label' }, hasPush ? 'Scan QR code instead' : 'Continue with Privasys ID'),
            ),
        );

        // Divider before alternative methods
        const hasAlternatives = hasWebAuthn || socialProviders.length > 0;
        if (hasAlternatives) {
            buttons.push(el('div', { className: 'divider' }, el('span', null, 'or')));
        }

        // Passkey button
        if (hasWebAuthn) {
            buttons.push(
                el('button', { className: 'btn-provider', onClick: () => this.startPasskey('authenticate') },
                    el('span', { html: ICON_PASSKEY }),
                    el('span', { className: 'btn-label' }, 'Passkey'),
                    el('span', { className: 'btn-hint' }, 'Face ID, Touch ID, Windows Hello'),
                ),
            );
        }

        // Social IdP buttons
        const socialIcons: Record<string, string> = {
            github: ICON_GITHUB,
            google: ICON_GOOGLE,
            microsoft: ICON_MICROSOFT,
            linkedin: ICON_LINKEDIN,
        };
        const socialNames: Record<string, string> = {
            github: 'GitHub',
            google: 'Google',
            microsoft: 'Microsoft',
            linkedin: 'LinkedIn',
        };
        for (const provider of socialProviders) {
            const icon = socialIcons[provider] ?? '';
            const name = socialNames[provider] ?? provider;
            buttons.push(
                el('button', {
                    className: 'btn-provider',
                    onClick: () => this.startSocial(provider),
                },
                    icon ? el('span', { html: icon }) : null,
                    el('span', { className: 'btn-label' }, name),
                ),
            );
        }

        return el('div', null,
            el('h2', { className: 'auth-panel-heading' }, `Sign in to ${displayName}`),
            ...buttons,
        );
    }

    private renderQR(): HTMLElement {
        const client = this.getRelayClient();
        const { payload } = client.createQR(this.sessionId);

        return el('div', null,
            el('div', { className: 'qr-section' },
                el('div', { className: 'qr-frame', html: renderQRSvg(payload) }),
                el('div', { className: 'scan-label' },
                    el('span', { className: 'pulse' }),
                    'Scan with Privasys Wallet',
                ),
            ),
        );
    }

    private renderPushWaiting(): HTMLElement {
        const hasWebAuthn = WebAuthnClient.isSupported();
        return el('div', null,
            el('div', { className: 'progress-section' },
                el('div', { className: 'spinner' }),
                el('div', { className: 'steps' },
                    el('div', { className: 'step done' },
                        el('span', { className: 'step-icon' }, '\u2713'), 'Notification sent',
                    ),
                    el('div', { className: 'step active' },
                        el('span', { className: 'step-icon' }, '\u2022'), 'Waiting for Privasys ID\u2026',
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
                el('button', { className: 'btn-provider', onClick: () => { this.cleanup(); this.startWallet(); } },
                    el('span', { html: ICON_LOGO }),
                    el('span', { className: 'btn-label' }, 'Scan QR code instead'),
                ),
                hasWebAuthn ? el('button', { className: 'btn-provider', onClick: () => { this.cleanup(); this.startPasskey('authenticate'); } },
                    el('span', { html: ICON_PASSKEY }),
                    el('span', { className: 'btn-label' }, 'Passkey'),
                ) : null,
            ),
        );
    }

    private renderWalletProgress(): HTMLElement {
        const isAuth = this.state === 'authenticating';
        const viaPush = !!this.cfg.pushToken && this.state !== 'qr-scanning';
        const firstStep = viaPush ? 'Notification sent' : 'QR code scanned';
        return el('div', null,
            el('div', { className: 'progress-section' },
                el('div', { className: 'spinner' }),
                el('div', { className: 'steps' },
                    el('div', { className: 'step done' },
                        el('span', { className: 'step-icon' }, '\u2713'), firstStep,
                    ),
                    el('div', { className: `step ${isAuth ? 'done' : 'active'}` },
                        el('span', { className: 'step-icon' }, isAuth ? '\u2713' : '\u2022'), 'Verifying server attestation',
                    ),
                    el('div', { className: `step ${isAuth ? 'active' : ''}` },
                        el('span', { className: 'step-icon' }, '\u2022'), 'FIDO2 biometric ceremony',
                    ),
                ),
            ),
        );
    }

    private renderPasskeyProgress(): HTMLElement {
        const phase = this.state;
        return el('div', null,
            el('h2', { className: 'auth-panel-heading' },
                phase === 'passkey-requesting' ? 'Preparing\u2026' : 'Verify your identity',
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
        );
    }

    private renderSuccess(): HTMLElement {
        const masked = this.sessionToken
            ? '\u25CF'.repeat(8) + this.sessionToken.slice(-6)
            : '\u2014';

        const methodLabel = this.method === 'wallet' ? 'Privasys ID' : 'Passkey';
        const methodDetail = this.method === 'wallet' ? 'Attestation verified' : 'This device';

        return el('div', null,
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
        return el('div', null,
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
                this.attributes = result.attributes;
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
        const { sessionId } = client.createQR(this.cfg.sessionId);
        this.sessionId = sessionId;
        this.state = 'qr-scanning';
        this.render();

        client.waitForResult(sessionId).then(
            (result) => {
                this.sessionToken = result.sessionToken;
                this.attestation = result.attestation;
                this.sessionId = result.sessionId;
                this.pushToken = result.pushToken;
                this.attributes = result.attributes;
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
            let result;
            if (op === 'register') {
                result = await client.register(globalThis.location?.hostname ?? 'user');
            } else {
                try {
                    result = await client.authenticate();
                } catch (authErr: any) {
                    // If no credentials found, automatically try registration
                    if (authErr?.message?.includes('no credentials') || authErr?.message?.includes('not found')) {
                        this.state = 'passkey-requesting';
                        this.render();
                        result = await client.register(globalThis.location?.hostname ?? 'user');
                    } else {
                        throw authErr;
                    }
                }
            }
            this.sessionToken = result.sessionToken;
            this.sessionId = result.sessionId;
            this.complete();
        } catch (err: any) {
            this.state = 'error';
            this.errorMsg = err?.message ?? 'Passkey authentication failed';
            this.render();
        }
    }

    private async startSocial(provider: string): Promise<void> {
        if (!this.cfg.onSocialAuth) return;
        this.state = 'authenticating';
        this.render();
        try {
            await this.cfg.onSocialAuth(provider);
            this.method = 'wallet';
            this.sessionToken = '';
            this.sessionId = this.cfg.sessionId ?? '';
            this.complete();
        } catch (err: any) {
            this.state = 'error';
            this.errorMsg = err?.message ?? `${provider} authentication failed`;
            this.render();
        }
    }

    private complete(): void {
        this.state = 'success';
        this.render();

        setTimeout(() => {
            const result: SignInResult = {
                sessionToken: this.sessionToken,
                method: this.method,
                attestation: this.attestation,
                sessionId: this.sessionId,
                pushToken: this.pushToken,
                attributes: this.attributes,
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
                requestedAttributes: this.cfg.requestedAttributes,
                appName: this.cfg.appName,
                privacyPolicyUrl: this.cfg.privacyPolicyUrl,
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
                sessionId: this.cfg.sessionId,
                fido2Base: this.cfg.fido2Base,
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
