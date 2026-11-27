// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The gate's stylesheet, injected into its shadow root.
 */

export const MODAL_CSS = /* css */ `
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
    opacity: 0;
    animation: fadeIn 0.15s ease forwards;
}
@keyframes fadeIn { to { opacity: 1; } }
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
}

/* Left: brand panel */
.brand-panel {
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 64px 48px 64px 64px;
    min-width: 360px;
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

/* Inline presentation — embedded in an adopter-provided container. The
   embedding page owns the surrounding chrome (brand content, dismissal),
   so render a single compact column; the host sizes the iframe to the
   column's height (AuthUIConfig.onContentHeight). Brand panel and close button
   are not rendered in this mode (see AuthUI.render). */
:host(.inline) .page {
    grid-template-columns: 1fr;
    grid-template-rows: 1fr auto;
    /* Sized by its content, not the frame's viewport: this is the height
       the embedding page is told to give the frame (AuthUI.sizeObserver). */
    min-height: 0;
}
:host(.inline) .auth-panel {
    padding: 24px 28px;
    width: 100%;
    max-width: 420px;
    margin: 0 auto;
    justify-content: center;
}
:host(.inline) .mobile-progress-header { display: flex; }
:host(.inline) .btn-back { margin-bottom: 16px; }
:host(.inline) .btn-hint { display: none; }
:host(.inline) .footer { padding: 12px 24px; }

/* Page presentation — the SDK renders the whole gate, with the adopter's
   pitch content (constrained plain strings) in the left panel. */
:host(.page-mode) .mobile-progress-header { display: flex; }
:host(.page-mode) .page { grid-template-rows: auto 1fr auto; }
.gate-header {
    grid-column: 1 / -1;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 24px;
    border-bottom: 1px solid #E2E8F0;
    font-size: 13px;
    color: #64748B;
}
.gate-header-logo { width: 22px; height: 22px; flex-shrink: 0; }
.gate-header-logo svg { width: 100%; height: 100%; display: block; }
.gate-header-applogo {
    width: 22px;
    height: 22px;
    flex-shrink: 0;
    object-fit: contain;
}
.gate-header-brand {
    font-size: 14px;
    font-weight: 600;
    letter-spacing: -0.01em;
    color: #0F172A;
}
.gate-seal {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: #64748B;
}
.gate-seal-logo { width: 15px; height: 15px; flex-shrink: 0; }
.gate-seal-logo svg { width: 100%; height: 100%; display: block; }
.gate-seal-text strong { color: #0F172A; font-weight: 600; }
.gate-close {
    margin-left: 14px;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    border: 1px solid #E2E8F0;
    border-radius: 999px;
    padding: 5px 13px;
    font-family: inherit;
    font-size: 12px;
    color: #475569;
    background: transparent;
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s;
}
.gate-close:hover { background: #F1F5F9; border-color: #CBD5E1; }
.gate-close-x { font-size: 11px; color: #94A3B8; }
.gate-request {
    font-size: 13px;
    color: #64748B;
    text-align: center;
    margin-bottom: 10px;
}
.gate-request strong { color: #0F172A; font-weight: 600; }
.hint-warn { color: #B45309; }
.pitch-logo {
    display: block;
    height: 44px;
    width: auto;
    max-width: 220px;
    object-fit: contain;
    margin-bottom: 20px;
}
.pitch-title {
    font-size: 30px;
    font-weight: 600;
    letter-spacing: -0.02em;
    color: #0F172A;
    margin-bottom: 16px;
}
.pitch-desc {
    font-size: 15px;
    color: #64748B;
    line-height: 1.65;
    margin-bottom: 24px;
    max-width: 420px;
}
.pitch-bullets {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 12px;
    max-width: 440px;
}
.pitch-bullet {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    font-size: 14px;
    color: #0F172A;
    line-height: 1.5;
}
.pitch-check {
    margin-top: 1px;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    border-radius: 50%;
    background: #00BCF2;
    color: #fff;
}
.pitch-check svg { width: 12px; height: 12px; }
@media (max-width: 768px) {
    /* Compact brand header on mobile hides the pitch body, same as the
       generic brand description; the gate header carries identity. */
    .pitch-body { display: none; }
    :host(.page-mode) .page { grid-template-rows: auto auto 1fr auto; }
    .gate-header { padding: 12px 16px; }
    /* Narrow screens: the seal collapses to the Privasys mark alone. */
    .gate-seal-text { display: none; }
}
@media (prefers-color-scheme: dark) {
    .pitch-title { color: #F1F5F9; }
    .pitch-desc { color: #94A3B8; }
    .pitch-bullet { color: #E2E8F0; }
    .gate-header { border-color: rgba(255,255,255,0.08); color: #94A3B8; }
    .gate-header-brand { color: #F1F5F9; }
    .gate-seal { color: #94A3B8; }
    .gate-seal-text strong { color: #E2E8F0; }
    .gate-close { border-color: rgba(255,255,255,0.12); color: #94A3B8; }
    .gate-close:hover { background: rgba(255,255,255,0.06); border-color: rgba(255,255,255,0.2); }
    .gate-request { color: #94A3B8; }
    .gate-request strong { color: #E2E8F0; }
    .hint-warn { color: #FBBF24; }
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
    text-decoration: none; /* also rendered as an <a> (wallet handoff) */
    box-sizing: border-box;
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
.btn-provider img {
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    object-fit: contain;
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
    color: #64748B;
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
    padding: 2px 0;
    min-height: 24px;
}
.link-btn:hover { text-decoration: underline; }
.link-btn.decline-btn {
    margin-top: 16px;
    font-size: 13px;
    display: block;
    text-align: center;
    width: 100%;
    color: #B91C1C;
}

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
.step.done   { color: #0F172A; }
.step.done .step-icon { color: #059669; }
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

/* Brand progress steps (left column during flow states) */
.brand-progress {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    margin-top: 28px;
}
.brand-progress .steps {
    max-width: none;
    gap: 6px;
}
.brand-progress .step {
    font-size: 14px;
    gap: 10px;
    padding: 4px 0;
}
.brand-progress .step-icon {
    width: 20px;
    font-size: 14px;
}
.brand-progress .spinner {
    width: 28px;
    height: 28px;
    border-width: 2.5px;
    margin-bottom: 8px;
}
.brand-progress .brand-progress-label {
    font-size: 14px;
    font-weight: 600;
    color: #059669;
    margin-top: 16px;
}
.brand-progress .success-method {
    margin-top: 8px;
    margin-bottom: 0;
}
@media (max-width: 768px) {
    .brand-progress { display: none; }
    .auth-panel .mobile-progress-header { display: flex; }
}
.mobile-progress-header {
    display: none;
    flex-direction: column;
    align-items: center;
    margin-bottom: 20px;
    width: 100%;
}
.mobile-progress-header .brand-progress { display: flex; align-items: center; }
.mobile-progress-header .steps { align-items: flex-start; width: 100%; max-width: 280px; }
.mobile-progress-header .step { font-size: 13px; }
.mobile-progress-header .spinner { width: 24px; height: 24px; border-width: 2px; margin-bottom: 6px; }
.mobile-progress-header .brand-progress-label {
    font-size: 13px;
    font-weight: 600;
    color: #059669;
    margin-top: 10px;
}
.mobile-progress-header .success-method {
    margin-top: 6px;
    margin-bottom: 0;
    justify-content: center;
}
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
    color: #64748B;
    text-align: center;
}

/* Visible on every button and link, in every theme. */
button:focus-visible, a:focus-visible {
    outline: 2px solid #2563EB;
    outline-offset: 2px;
}

/* Dark mode */
@media (prefers-color-scheme: dark) {
    :host { color: #E2E8F0; background: #0F172A; }
    button:focus-visible, a:focus-visible { outline-color: #93C5FD; }
    .btn-close { color: #64748B; }
    .btn-close:hover { background: rgba(255,255,255,0.06); color: #94A3B8; }
    .btn-back { color: #64748B; }
    .btn-back:hover { background: rgba(255,255,255,0.06); color: #E2E8F0; }
    .brand-panel-name { color: #F1F5F9; }
    .brand-panel-desc { color: #94A3B8; }
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
    /* Primary buttons invert in dark mode (light pill) — the label MUST
       invert with them or it is light-on-light and unreadable (observed
       on the mobile wallet handoff). */
    .btn-provider.primary .btn-label { color: #0F172A; }
    .btn-hint { color: #94A3B8; }
    .btn-label { color: #E2E8F0; }
    .divider { color: #475569; }
    .divider::before, .divider::after { background: rgba(255,255,255,0.08); }
    .scan-hint { color: #64748B; }
    .qr-frame { border-color: rgba(255,255,255,0.1); background: #1E293B; }
    .step { color: #64748B; }
    .step.active { color: #E2E8F0; }
    .step.done { color: #E2E8F0; }
    .step.done .step-icon { color: #34D399; }
    .spinner { border-color: rgba(255,255,255,0.08); border-top-color: #F1F5F9; }
    .session-info { border-color: rgba(255,255,255,0.08); }
    .session-row + .session-row { border-color: rgba(255,255,255,0.08); }
    .session-label { color: #64748B; }
    .method-detail { color: #64748B; }
    .error-msg { color: #64748B; }
    .btn-retry { background: rgba(255,255,255,0.04); border-color: rgba(255,255,255,0.1); color: #E2E8F0; }
    .btn-retry:hover { background: rgba(255,255,255,0.07); }
    .footer { border-color: rgba(255,255,255,0.06); color: #94A3B8; }
    .footer .link-btn { color: #93C5FD; }
    .scan-label { color: #E2E8F0; }

    .error-title { color: #E2E8F0; }
}
`;
