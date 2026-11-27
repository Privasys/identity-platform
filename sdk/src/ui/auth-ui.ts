// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import { isGovVerified } from '../attributes';
import { attributeLabel, assuranceLabel } from '../attributes-ui';
import { PrivasysAuth } from '../client';
import { alternativeOrder, displayAppName, gateOrder } from '../gate';
import { type GateChoice, type GateOptions, type GateProvider, finishOnSuccess } from '../gate-headless';
import { providerButtonLabel, providerName } from '../providers';
import { themeClasses, themeProperties, themeStylesheet } from '../theme';
import type { AuthState, AttestationInfo, SessionRelayBinding } from '../types';
import { type WebAuthnState, WebAuthnClient } from '../webauthn';
import type { AuthUIConfig, SignInResult, UIState } from './config';
import { el, isMobileDevice, walletSchemeUrl } from './dom';
import { ICON_LOGO, ICON_PASSKEY, ICON_CHECK_CIRCLE, ICON_X_CIRCLE, ICON_PHONE, ICON_GITHUB, ICON_GOOGLE, ICON_MICROSOFT, ICON_LINKEDIN, SOCIAL_ICONS, ICON_CLOSE, ICON_SHIELD, ICON_ARROW_LEFT, ICON_PITCH_CHECK } from './icons';
import { renderQRSvg } from './qr-render';
import { MODAL_CSS } from './styles';

/**
 * Built-in authentication UI overlay for Privasys enclaves.
 *
 * Shows a centered sign-in modal (similar to Google / Microsoft) with:
 * - **Continue with Privasys ID** — QR code + broker relay
 * - **Sign in with passkey** — Browser WebAuthn (Touch ID, Windows Hello)
 *
 * Usage:
 * ```ts
 * const ui = new Privasys.AuthUI({ appName: 'my-app', clientId: 'my-client' });
 * const result = await ui.signIn();
 * console.log(result.sessionToken);
 * ```
 *
 * The modal is rendered inside an isolated Shadow DOM so its styles never
 * leak into or conflict with the host page.
 */
export class AuthUI {
    private readonly cfg: Required<Pick<AuthUIConfig, 'appName' | 'brokerUrl' | 'timeout'>> & AuthUIConfig;
    private host: HTMLElement | null = null;
    private shadow: ShadowRoot | null = null;
    private sizeObserver: ResizeObserver | null = null;
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
    private deviceLabel: string | undefined;
    private attributes: Record<string, string> | undefined;
    private sessionRelay: SessionRelayBinding | undefined;
    private method: 'wallet' | 'passkey' | 'social' = 'wallet';
    // The provider's name, once the person chose a social sign-in.
    private socialName = '';

    /** How the gate names the method on its outcome. */
    private methodLabel(): string {
        return this.method === 'wallet' ? 'Privasys ID' : this.method === 'passkey' ? 'Passkey' : this.socialName;
    }
    private qrPayload = '';
    // True when signIn() skipped idle and went straight into a flow — the
    // ceremony's FIRST screen is then `autoFirstScreen` and Back has
    // nowhere meaningful to go (its alternatives are offered inline).
    private autoStarted = false;
    private autoFirstScreen: UIState | null = null;
    /** The outcome is on screen for good (see AuthUIConfig.finalScreen). */
    private finished = false;
    /** The request was refused from the gate (see AuthUIConfig.decline). */
    private declined = false;
    private declining = false;
    // Mobile handoff: whether the user expanded the QR ("scan with another
    // device") instead of using the Open-in-Wallet button.
    private showQrOnMobile = false;
    // Set when the wallet handoff visibly failed (page never lost focus
    // after the tap — the app is most likely not installed).
    private walletOpenFailed = false;
    // Completion watcher (same-device recovery, see cfg.checkComplete).
    private completeWatch: { timer: ReturnType<typeof setInterval>; onVis: () => void } | null = null;
    private viaPoll = false;

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

    /** Whether a sign-in method is offered (methods config; default all). */
    private allowed(m: 'wallet' | 'passkey' | 'social'): boolean {
        return !this.cfg.methods || this.cfg.methods.includes(m);
    }

    /** The single offered method, when the idle menu would have exactly one
     *  option — used to skip the menu and start that flow directly. */
    private singleOption(): 'wallet' | 'passkey' | null {
        const wallet = this.allowed('wallet');
        const passkey = this.allowed('passkey') && WebAuthnClient.isSupported();
        const social = this.allowed('social') ? (this.cfg.socialProviders?.length ?? 0) : 0;
        if (wallet && !passkey && social === 0) return 'wallet';
        if (!wallet && passkey && social === 0) return 'passkey';
        return null;
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
            this.sessionRelay = undefined;
            this.qrPayload = '';
            this.autoStarted = false;
            this.autoFirstScreen = null;
            this.showQrOnMobile = false;
            this.walletOpenFailed = false;
            this.viaPoll = false;
            this.finished = false;
            this.declined = false;
            this.declining = false;
            this.mount();

            if (this.cfg.operationApproval) {
                // An operation to approve: the wallet already has it.
                this.autoStarted = true;
                this.autoFirstScreen = 'approve-waiting';
                this.startOperationApproval();
            } else if (this.cfg.approveFlow) {
                // Re-verification of an existing session: approval push only.
                this.autoStarted = true;
                this.autoFirstScreen = 'approve-waiting';
                this.startApprove();
            } else if (this.cfg.headless) {
                // The page chooses; nothing starts until it does.
                this.render();
            } else if (this.cfg.pushToken && this.allowed('wallet') && this.chooser().length < 2) {
                // Returning user (push token available): skip idle, push.
                // With several wallets remembered the person chooses first.
                this.autoStarted = true;
                this.autoFirstScreen = 'push-waiting';
                this.startPush();
            } else if (this.singleOption() === 'wallet' && !(this.cfg.lookupDevice && !isMobileDevice())) {
                // The site's own chooser already picked Privasys (methods:
                // ['wallet'] with no push token) — go straight to the QR.
                // Where the host can look the phone up, the one button shows
                // instead: the lookup is a popup, and a popup needs a click.
                this.autoStarted = true;
                this.autoFirstScreen = 'qr-scanning';
                this.startWallet();
            } else {
                this.render();
            }
        });
    }

    /** Close the modal without completing authentication. */
    close(): void {
        this.cleanup();
        this.sizeObserver?.disconnect();
        this.sizeObserver = null;
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
        if (this.cfg.presentation === 'inline') this.host.classList.add('inline');
        else if (this.cfg.presentation === 'page') this.host.classList.add('page-mode');
        this.shadow = this.host.attachShadow({ mode: 'closed' });

        const style = document.createElement('style');
        style.textContent = MODAL_CSS;
        if (this.cfg.theme) {
            // Values go on the host as properties; the sheet only reads them.
            for (const c of themeClasses(this.cfg.theme)) this.host.classList.add(c);
            for (const [k, v] of Object.entries(themeProperties(this.cfg.theme))) this.host.style.setProperty(k, v);
            style.textContent += themeStylesheet(this.cfg.theme);
        }
        this.shadow.appendChild(style);

        const container = this.cfg.container ?? document.body;
        container.appendChild(this.host);
        // Tell the host how tall the content is, on every change: an iframe
        // cannot measure a cross-origin document itself.
        // The host fills the frame's viewport (fixed, inset 0), so its
        // height is the frame's own, not the content's: the embedding page
        // would be told the height it chose and the gate could never grow
        // past it. The observed element is the rendered page, which inline
        // CSS lets shrink to its content; render() re-points the observer
        // at each new page element.
        if (this.cfg.onContentHeight && typeof ResizeObserver !== 'undefined') {
            const cb = this.cfg.onContentHeight;
            this.sizeObserver = new ResizeObserver((entries) => {
                const target = entries[entries.length - 1]?.target;
                if (target) cb(target.getBoundingClientRect().height);
            });
        }
    }

    /** The sign-in options a headless page draws, as this gate would. */
    gateOptions(): GateOptions {
        const icons: Record<string, string> = { github: ICON_GITHUB, google: ICON_GOOGLE, microsoft: ICON_MICROSOFT, linkedin: ICON_LINKEDIN };
        const social = this.allowed('social');
        return {
            own: social ? (this.cfg.socialOwn ?? []).map((o) => ({ ...o, icon: icons[o.provider] })) : [],
            providers: social
                ? (this.cfg.socialProviders ?? []).map((p) => ({ id: p as GateProvider['id'], name: providerName(p), icon: icons[p] }))
                : [],
            wallet: this.allowed('wallet'),
            push: !!this.cfg.pushToken && this.allowed('wallet'),
            ...(this.chooser().length > 1
                ? { wallets: this.chooser().map((d, i) => ({ id: String(i), label: d.label })) }
                : {}),
        };
    }

    /** The remembered wallets to choose from, when the wallet is offered. */
    private chooser(): { pushToken: string; label: string }[] {
        return this.allowed('wallet') ? (this.cfg.devices ?? []) : [];
    }

    // The person asked for another Privasys ID than the remembered ones: the
    // QR sign-in that follows asks whether to remember it, as a first one does.
    private addingDevice = false;

    private pushTo(device: { pushToken: string }): void {
        this.addingDevice = false;
        this.cfg.pushToken = device.pushToken;
        this.startPush();
    }

    private useAnotherWallet(): void {
        this.addingDevice = true;
        this.cfg.pushToken = undefined;
        this.startWallet();
    }

    private forget(device: { pushToken: string }): void {
        if (this.lookingUp) return;
        this.lookingUp = true;
        void Promise.resolve(this.cfg.forgetDevice?.(device.pushToken)).catch(() => undefined).then(() => {
            this.lookingUp = false;
            this.cfg.devices = (this.cfg.devices ?? []).filter((d) => d.pushToken !== device.pushToken);
            this.cfg.pushToken = this.cfg.devices[0]?.pushToken;
            if (this.state === 'idle') this.render();
        });
    }

    /** Start the flow a headless page chose, if the gate offers it. A
     *  choice outside the offer, or while a flow runs, is ignored. */
    start(choice: GateChoice): void {
        // While a push waits, the page may switch to the QR code, as the
        // visible gate's "Scan QR code instead" does.
        if (this.state === 'push-waiting' && choice.method === 'wallet' && choice.qr && this.allowed('wallet')) {
            this.cleanup();
            this.startWallet();
            return;
        }
        if (this.state !== 'idle' && this.state !== 'error') return;
        this.errorMsg = '';
        if (choice.method === 'social') {
            if (!this.allowed('social')) return;
            const offered = choice.own
                ? (this.cfg.socialOwn ?? []).some((o) => o.provider === choice.provider)
                : (this.cfg.socialProviders ?? []).includes(choice.provider);
            if (!offered) return;
            void this.startSocial(choice.provider, !!choice.own);
            return;
        }
        if (!this.allowed('wallet')) return;
        const chosen = choice.wallet !== undefined ? this.chooser()[Number(choice.wallet)] : undefined;
        if (chosen && !choice.qr) this.pushTo(chosen);
        else if (choice.qr && this.chooser().length > 1) this.useAnotherWallet();
        else if (choice.qr) this.startWallet();
        else if (this.cfg.pushToken) this.startPush();
        else void this.startWalletFromClick();
    }

    private lookingUp = false;

    /**
     * The wallet button with no phone known on this site: ask the host
     * whether this browser knows one (a popup, so this runs inside the
     * click), and send the notification if it does. Otherwise the QR code,
     * as before. A phone needs no lookup: the wallet opens on it directly.
     */
    private async startWalletFromClick(): Promise<void> {
        if (this.lookingUp) return;
        if (!this.cfg.pushToken && this.cfg.lookupDevice && !isMobileDevice()) {
            this.lookingUp = true;
            const known = await this.cfg.lookupDevice().catch(() => []);
            this.lookingUp = false;
            if (this.state !== 'idle' && this.state !== 'error') return;
            if (known.length > 1 && !this.cfg.headless) {
                // Several wallets are known to this browser: let the person choose.
                this.cfg.devices = known;
                this.cfg.pushToken = known[0].pushToken;
                this.state = 'idle';
                this.render();
                return;
            }
            if (known.length) {
                this.pushTo(known[0]);
                return;
            }
        }
        this.startWallet();
    }

    private render(): void {
        this.cfg.onGateState?.({
            state: this.state,
            ...(this.state === 'qr-scanning' && this.qrPayload ? { qr: this.qrPayload, qrSvg: renderQRSvg(this.qrPayload) } : {}),
            ...(this.state === 'error' && this.errorMsg ? { error: this.errorMsg } : {}),
        });
        if (!this.shadow) return;
        // Remove old content (keep style)
        const style = this.shadow.querySelector('style')!;
        this.shadow.innerHTML = '';
        this.shadow.appendChild(style);

        const displayName = displayAppName(this.cfg.appName);
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
            case 'approve-waiting':
                brandDesc = 'Check your phone \u2014 approve the connection to continue.';
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
                brandDesc = '';
                break;
            case 'error':
                brandDesc = 'Something went wrong. You can try again or choose a different method.';
                break;
            default:
                brandDesc = `<strong>${displayName}</strong> needs to verify your identity. Please choose one of the authentication options.`;
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
            case 'approve-waiting':
                content = this.renderApproveWaiting();
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

        // Inline embeds get no chrome of their own: the embedding page owns
        // the brand content and dismissal (AuthFrame.cancel()). Page mode
        // renders the whole gate — pitch panel left, no close button.
        const presentation = this.cfg.presentation ?? 'modal';
        const inline = presentation === 'inline';
        const isPage = presentation === 'page';

        // Progress steps earn their place only once the ceremony is actually
        // underway. While merely waiting on the user (push tile, QR code,
        // approval tile) all but the first step are inert, and the tile/QR
        // already says what is happening — showing four dormant bullets
        // above it reads as clutter. On success the outcome is the message,
        // not the path that led there — renderSuccess shows a single tile
        // instead. The brand panel's copy of the steps (modal desktop)
        // keeps its always-on behaviour.
        const stepsUnderway = !['push-waiting', 'qr-scanning', 'approve-waiting', 'success'].includes(this.state);

        // Without a generic brand panel to carry context (inline and page
        // modes), flow states get a heading of their own above the tile.
        const flowHeading = (inline || isPage) && !isIdle && this.state !== 'success' && this.state !== 'error'
            ? (this.cfg.operationApproval ? 'Approve in your Privasys Wallet'
                : this.method === 'passkey' ? 'Sign in with a passkey'
                    : this.method === 'social' ? `Signing in with ${this.socialName}` : 'Connecting you to Privasys ID')
            : null;

        // Left panel content: the adopter's pitch (page mode — that panel is
        // then the CONSUMER's space: their logo/content, no Privasys header,
        // no progress steps; Privasys identity lives in the gate header) or
        // the generic Privasys brand copy.
        const pitch = this.cfg.pitch;
        const pitchOwned = isPage && !!pitch;
        const leftPanel = inline ? null : el('div', { className: 'brand-panel' },
            pitchOwned ? null : el('div', { className: 'brand-panel-header' },
                el('div', { className: 'brand-panel-logo', html: ICON_LOGO }),
                el('div', { className: 'brand-panel-name' }, 'Privasys'),
            ),
            pitchOwned ? el('div', { className: 'pitch-body' },
                pitch!.logoUrl ? el('img', { className: 'pitch-logo', src: pitch!.logoUrl, alt: '' }) : null,
                pitch!.title ? el('h1', { className: 'pitch-title' }, pitch!.title) : null,
                pitch!.description ? el('p', { className: 'pitch-desc' }, pitch!.description) : null,
                pitch!.bullets?.length ? el('ul', { className: 'pitch-bullets' },
                    ...pitch!.bullets.map((b) => el('li', { className: 'pitch-bullet' },
                        el('span', { className: 'pitch-check', html: ICON_PITCH_CHECK }),
                        b,
                    )),
                ) : null,
            ) : (brandDesc ? el('p', { className: 'brand-panel-desc', html: brandDesc }) : null),
            (this.isFlowState() && !pitchOwned) ? this.renderBrandProgress() : null,
        );

        // Page mode: the templated gate header is APP-LED — the consumer's
        // logo and name lead, "Secured by Privasys ID" is the trust seal,
        // and Close hands control back to the app (connect() rejects with
        // 'cancelled'). The request statement lives above the ceremony.
        const appDisplay = this.cfg.app?.displayName || displayName;

        const page = el('div', { className: 'page' },
            isPage ? el('div', { className: 'gate-header' },
                this.cfg.app?.logoUrl
                    ? el('img', { className: 'gate-header-applogo', src: this.cfg.app.logoUrl, alt: '' })
                    : el('div', { className: 'gate-header-logo', html: ICON_LOGO }),
                el('span', { className: 'gate-header-brand' }, appDisplay),
                el('span', { className: 'gate-seal' },
                    el('span', { className: 'gate-seal-logo', html: ICON_LOGO }),
                    el('span', { className: 'gate-seal-text' },
                        'Secured by ',
                        el('strong', null, 'Privasys ID'),
                    ),
                ),
                // Once the outcome is on screen for good there is nothing to close.
                this.finished ? null : el('button', { className: 'gate-close', onClick: () => this.handleCancel() },
                    el('span', { className: 'gate-close-x' }, '✕'),
                    'Close',
                ),
            ) : null,
            // Close button — modal overlays only (a page is not dismissable
            // from inside; adopters cancel via AuthFrame.cancel()).
            (inline || isPage) ? null : el('button', { className: 'btn-close', html: ICON_CLOSE, onClick: () => this.handleCancel() }),
            leftPanel,
            // Right: auth panel
            el('div', { className: `auth-panel${isIdle ? '' : ' auth-panel--centered'}` },
                // No Back on success or error (Try again covers it), on the
                // screen an auto-started flow began at (idle was never
                // shown; alternatives are inline), or anywhere in the
                // approve-only flow (no idle menu exists there — "Sign in
                // another way" is the escape hatch).
                (!isIdle && this.state !== 'success' && this.state !== 'error' && !this.cfg.approveFlow
                    && !(this.autoStarted && this.state === this.autoFirstScreen))
                    ? el('button', { className: 'btn-back', onClick: () => this.goBack() },
                        el('span', { html: ICON_ARROW_LEFT }),
                        'Back',
                    ) : null,
                // Page mode: the request statement sits right above the
                // ceremony heading — where the user is already looking —
                // answering WHY this screen is shown.
                (isPage && flowHeading) ? el('p', { className: 'gate-request' },
                    el('strong', null, appDisplay),
                    this.cfg.operationApproval ? ' asks for your approval' : ' wants to authenticate you',
                ) : null,
                flowHeading ? el('h2', { className: 'auth-panel-heading' }, flowHeading) : null,
                // Shown when the brand panel carries no progress steps:
                // always in inline mode, and on the mobile breakpoint (where
                // the brand panel collapses to a compact header).
                (this.isFlowState() && stepsUnderway) ? el('div', { className: 'mobile-progress-header' }, this.renderBrandProgress()) : null,
                content,
                // Refusing the request sits with the ceremony, while it waits.
                (this.cfg.decline && !this.finished
                    && ['idle', 'qr-scanning', 'push-waiting', 'approve-waiting'].includes(this.state))
                    ? el('button', {
                        className: 'link-btn decline-btn',
                        onClick: () => this.runDecline(),
                    }, this.declining ? 'Declining…' : this.cfg.decline.label)
                    : null,
            ),
            // Footer spans both columns
            (this.cfg.legal === false && (inline || isPage)) ? null : el('div', { className: 'footer' },
                'By continuing, you agree to the ',
                el('a', { href: 'https://privasys.org/legal/terms', target: '_blank', className: 'link-btn', style: 'font-size:inherit' }, 'Terms of Service'),
                ' and ',
                el('a', { href: 'https://privasys.org/legal/privacy', target: '_blank', className: 'link-btn', style: 'font-size:inherit' }, 'Privacy Policy'),
                '.',
            ),
        );

        this.shadow.appendChild(page);
        if (this.sizeObserver) {
            this.sizeObserver.disconnect();
            this.sizeObserver.observe(page);
        }
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
        const hasWebAuthn = WebAuthnClient.isSupported() && this.allowed('passkey');
        const hasPush = !!this.cfg.pushToken && this.allowed('wallet');
        const socialProviders = this.allowed('social') ? (this.cfg.socialProviders ?? []) : [];
        const hasWallet = this.allowed('wallet');
        const displayName = this.cfg.app?.displayName || displayAppName(this.cfg.appName);

        const buttons: (HTMLElement | null | false)[] = [];

        // Several remembered wallets: one button each, the last used here
        // first, then the way to add another.
        const several = this.chooser();
        if (several.length > 1) {
            several.forEach((d, i) => {
                buttons.push(
                    el('button', { className: `btn-provider ${i === 0 ? 'primary' : ''}`, onClick: () => this.pushTo(d) },
                        el('span', { html: ICON_PHONE }),
                        el('span', { className: 'btn-label' }, d.label),
                        el('span', { className: 'btn-hint' }, 'Notification'),
                    ),
                    this.cfg.forgetDevice ? el('button', {
                        className: 'link-btn',
                        style: 'font-size: 12px; display: block; margin: 0 2px 12px auto; padding: 2px 0;',
                        onClick: () => this.forget(d),
                    }, 'Forget') : null,
                );
            });
            buttons.push(
                el('button', { className: 'btn-provider', onClick: () => this.useAnotherWallet() },
                    el('span', { html: ICON_LOGO }),
                    el('span', { className: 'btn-label' }, 'Use another Privasys ID'),
                ),
            );
        }

        // Push-first: returning user with push token
        if (hasPush && several.length < 2) {
            buttons.push(
                el('button', { className: 'btn-provider primary', onClick: () => this.startPush() },
                    el('span', { html: ICON_PHONE }),
                    el('span', { className: 'btn-label' }, 'Sign in with Privasys ID'),
                    el('span', { className: 'btn-hint' }, 'Notification'),
                ),
            );
        }

        // Primary wallet/QR button — Privasys logo in the button
        if (hasWallet && several.length < 2) {
            const altLabel = isMobileDevice() ? 'Open in Privasys Wallet instead' : 'Scan QR code instead';
            buttons.push(
                el('button', { className: `btn-provider ${hasPush ? '' : 'primary'}`, onClick: () => { if (hasPush) this.startWallet(); else void this.startWalletFromClick(); } },
                    el('span', { html: ICON_LOGO }),
                    el('span', { className: 'btn-label' }, hasPush ? altLabel : 'Continue with Privasys ID'),
                ),
            );
        }

        // Passkey button
        let passkeyButton: HTMLElement | null = null;
        if (hasWebAuthn) {
            const passkeyOp = this.getWebAuthnClient().sessions.hasPasskeyHint() ? 'authenticate' : 'register';
            passkeyButton = el('button', { className: 'btn-provider', onClick: () => this.startPasskey(passkeyOp) },
                el('span', { html: ICON_PASSKEY }),
                el('span', { className: 'btn-label' }, 'Passkey'),
                el('span', { className: 'btn-hint' }, 'Face ID, Touch ID, Windows Hello'),
            );
        }

        // Social IdP buttons
        const socialIcons = SOCIAL_ICONS;
        // One provider and nothing else to choose from (methods: ['social'],
        // providers: ['microsoft']): the button is the primary call to action
        // and carries the full label, so the gate reads as a sign-in page for
        // that identity rather than a chooser with one entry.
        const ownRegistrations = this.allowed('social') ? (this.cfg.socialOwn ?? []) : [];
        const soloSocial = !hasWallet && !hasWebAuthn && socialProviders.length === 1 && !ownRegistrations.length;
        // A client's own registrations beside the platform's (an organisation's
        // staff sign-in) come first among the alternatives, under the
        // organisation's name and icon; the platform's buttons follow for
        // everyone else.
        const ownButtons = ownRegistrations.map((own) =>
            el('button', { className: 'btn-provider', onClick: () => this.startSocial(own.provider, true) },
                own.iconUrl ? el('img', { src: own.iconUrl, alt: '' }) : el('span', { html: socialIcons[own.provider] ?? '' }),
                el('span', { className: 'btn-label' }, `Sign in with ${own.displayName}`),
            ));
        const socialButtons = socialProviders.map((provider) => {
            // A client with its own registration may bring its organisation's
            // icon (an https address the host sanitised), drawn as an image;
            // the brand icon stays for everyone else.
            const iconUrl = this.cfg.socialIcons?.[provider];
            const icon = socialIcons[provider] ?? '';
            return el('button', {
                className: soloSocial ? 'btn-provider primary' : 'btn-provider',
                onClick: () => this.startSocial(provider),
            },
                iconUrl ? el('img', { src: iconUrl, alt: '' }) : icon ? el('span', { html: icon }) : null,
                el('span', { className: 'btn-label' }, providerButtonLabel(provider, soloSocial, this.cfg.socialDisplayNames?.[provider])),
            );
        });

        // The alternatives, in the order the adopter listed the methods
        // (`['social', 'passkey']` puts the work account first). The "or"
        // divider separates them from the wallet; with no wallet offered
        // there is nothing to divide.
        const alternatives: HTMLElement[] = [];
        for (const method of alternativeOrder(this.cfg.methods)) {
            if (method === 'passkey' && passkeyButton) alternatives.push(passkeyButton);
            if (method === 'social') alternatives.push(...ownButtons, ...socialButtons);
        }
        // The adopter's list also says whether the wallet leads or follows
        // (`['social', 'wallet']` puts the work account above Privasys ID).
        // The first button on the gate is its primary action, whichever it is.
        const walletButtons = buttons.splice(0).filter((b): b is HTMLElement => !!b);
        const walletFirst = gateOrder(this.cfg.methods)[0] === 'wallet' || !alternatives.length;
        const divider = alternatives.length && walletButtons.length
            ? [el('div', { className: 'divider' }, el('span', null, 'or'))]
            : [];
        if (!walletFirst && walletButtons.length) {
            for (const b of walletButtons) b.classList.remove('primary');
            alternatives[0].classList.add('primary');
        }
        buttons.push(...(walletFirst ? [...walletButtons, ...divider, ...alternatives] : [...alternatives, ...divider, ...walletButtons]));

        return el('div', null,
            el('h2', { className: 'auth-panel-heading' }, `Sign in to ${displayName}`),
            ...buttons,
        );
    }

    private renderQR(): HTMLElement {
        // The QR payload is generated once in startWallet() and cached on
        // `this.qrPayload`. Re-running `createQR()` here would re-PUT the
        // descriptor to the relay on every render and trigger a chain of
        // 409 conflicts (one PUT per state transition).
        const payload = this.qrPayload;

        // Same-device handoff: on a phone the QR is un-scannable (the
        // wallet lives on THIS device), so the primary action opens the
        // wallet directly via the custom scheme. The QR stays available
        // behind a toggle for the cross-device case, and an install link
        // covers users without the wallet. Completion arrives via the
        // broker relay when it survives the app switch, or the IdP
        // status poll when it does not (startCompleteWatch).
        if (isMobileDevice() && !this.showQrOnMobile) {
            return el('div', null,
                el('a', {
                    className: 'btn-provider primary',
                    href: walletSchemeUrl(payload),
                    // Fallback for OLD frame clients only: _top at least
                    // reaches iOS. New clients bounce through the parent
                    // page instead (see onNavigate) — WebKit blocks
                    // cross-origin-iframe-initiated custom-scheme
                    // navigations with Safari's "address is invalid"
                    // alert even when the app is installed.
                    target: '_top',
                    style: 'margin-bottom: 4px;',
                    onClick: (e: Event) => {
                        this.watchWalletOpen();
                        if (this.cfg.onNavigate) {
                            e.preventDefault();
                            this.cfg.onNavigate(walletSchemeUrl(payload));
                        }
                    },
                },
                    el('span', { html: ICON_LOGO }),
                    el('span', { className: 'btn-label' }, 'Open in Privasys Wallet'),
                ),
                this.walletOpenFailed
                    ? el('p', { className: 'scan-hint hint-warn', style: 'max-width: none; text-align: center; margin-top: 12px;' },
                        'The wallet did not open. Install it first, or scan the QR code with another device.',
                    )
                    : el('p', { className: 'scan-hint', style: 'max-width: none; text-align: center; margin-top: 12px;' },
                        'Approve there, then come back to this tab.',
                    ),
                el('div', { className: 'divider' }, el('span', null, 'or')),
                el('a', {
                    className: 'link-btn',
                    href: 'https://privasys.id/',
                    target: '_blank',
                    rel: 'noreferrer',
                    style: 'font-size: 13px; display: block; text-align: center; width: 100%; margin-bottom: 10px;',
                }, 'Don’t have the app? Get the Privasys Wallet'),
                el('button', {
                    className: 'link-btn',
                    style: 'font-size: 13px; display: block; text-align: center; width: 100%;',
                    onClick: () => { this.showQrOnMobile = true; this.render(); },
                }, 'Scan the QR code with another device'),
            );
        }

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
        const hasWebAuthn = WebAuthnClient.isSupported() && this.allowed('passkey');
        return el('div', null,
            el('p', { className: 'btn-provider', style: 'margin-bottom: 20px; max-width: none; text-align: center;' },
                'Check your phone \u2014 tap the notification to approve this connection.',
            ),
            el('div', { className: 'divider' }, el('span', null, 'or')),
            el('div', { className: 'alt-actions' },
                el('button', { className: 'btn-provider', onClick: () => { this.cleanup(); this.startWallet(); } },
                    el('span', { html: ICON_LOGO }),
                    el('span', { className: 'btn-label' },
                        isMobileDevice() ? 'Open in Privasys Wallet instead' : 'Scan QR code instead'),
                ),
                hasWebAuthn ? el('button', { className: 'btn-provider', onClick: () => { this.cleanup(); this.startPasskey(this.getWebAuthnClient().sessions.hasPasskeyHint() ? 'authenticate' : 'register'); } },
                    el('span', { html: ICON_PASSKEY }),
                    el('span', { className: 'btn-label' }, 'Passkey'),
                ) : null,
            ),
        );
    }

    /** Approve-only flow: waiting for the one-tap wallet re-verification. */
    private renderApproveWaiting(): HTMLElement {
        if (this.cfg.operationApproval) return this.renderOperationApproval();
        const flow = this.cfg.approveFlow!;
        const why = flow.reason === 'workload-changed'
            ? `${flow.appLabel} was updated since you last verified it.`
            : flow.reason === 'enc-changed'
                ? `The platform hosting ${flow.appLabel} changed since you last verified it.`
                : flow.reason === 'attributes-widened'
                    ? `${flow.appLabel} is asking for more of your data than you previously shared.`
                    : `A fresh approval is needed to open a sealed channel to ${flow.appLabel}.`;
        // For a widened request, name exactly what was ADDED \u2014 the holder
        // decides on the difference, never on a re-listing of old grants.
        const delta = flow.reason === 'attributes-widened' && flow.added?.length
            ? el('div', { style: 'margin: 0 auto 16px; max-width: 320px; text-align: left;' },
                ...flow.added.map((key) => el('div', {
                    style: 'display: flex; justify-content: space-between; gap: 12px; ' +
                        'padding: 6px 10px; border: 1px solid #E2E8F0; border-radius: 8px; ' +
                        'margin-bottom: 6px; font-size: 13px;',
                },
                    el('span', { style: 'font-weight: 600;' }, attributeLabel(key)),
                    el('span', { style: 'color: #64748B;' }, isGovVerified(key) ? assuranceLabel(key) : ''),
                )),
            )
            : null;
        return el('div', null,
            el('p', { className: 'scan-hint', style: 'margin-bottom: 16px; max-width: none; text-align: center;' }, why),
            delta,
            el('p', { className: 'btn-provider', style: 'margin-bottom: 20px; max-width: none; text-align: center;' },
                `Check your phone \u2014 approve ${flow.appLabel} to continue.`,
            ),
            el('button', {
                className: 'link-btn',
                style: 'font-size: 13px; display: block; text-align: center; width: 100%;',
                onClick: () => this.finishApproveFallback(),
            }, 'Sign in another way'),
        );
    }

    /** An operation to approve: the wallet was notified when it was asked
     *  for, the QR code opens it in the wallet when the notification is late
     *  or never comes, and a passkey on this computer can approve it too. */
    private renderOperationApproval(): HTMLElement {
        const op = this.cfg.operationApproval!;
        const mobile = isMobileDevice();
        return el('div', null,
            el('p', { className: 'scan-hint', style: 'margin-bottom: 16px; max-width: none; text-align: center;' },
                mobile
                    ? 'A notification was sent to your phone. Approve it in your Privasys Wallet, or open the wallet here.'
                    : 'A notification was sent to your phone. Approve it in your Privasys Wallet, or scan this code if it has not arrived.',
            ),
            mobile
                ? el('a', {
                    className: 'btn-provider primary',
                    href: op.walletLink,
                    target: '_top',
                    onClick: (e: Event) => {
                        if (this.cfg.onNavigate) {
                            e.preventDefault();
                            this.cfg.onNavigate(op.walletLink);
                        }
                    },
                },
                    el('span', { html: ICON_LOGO }),
                    el('span', { className: 'btn-label' }, 'Open in Privasys Wallet'),
                )
                : el('div', { className: 'qr-section' },
                    el('div', { className: 'qr-frame', html: renderQRSvg(op.walletLink) }),
                    el('div', { className: 'scan-label' },
                        el('span', { className: 'pulse' }),
                        'Scan with Privasys Wallet',
                    ),
                ),
            op.onPasskey ? el('div', { className: 'divider' }, el('span', null, 'or')) : null,
            op.onPasskey ? el('button', {
                className: 'link-btn',
                style: 'font-size: 13px; display: block; text-align: center; width: 100%;',
                onClick: () => op.onPasskey?.(),
            }, 'Use a passkey on this computer') : null,
        );
    }

    private startOperationApproval(): void {
        const op = this.cfg.operationApproval!;
        this.method = 'wallet';
        this.state = 'approve-waiting';
        this.render();
        op.wait().then(
            () => this.complete(),
            (err: unknown) => {
                // Declined from this gate: its own outcome is already shown.
                if (this.declined) return;
                this.state = 'error';
                this.errorMsg = (err as Error)?.message ?? 'The approval was not completed.';
                this.finished = true;
                this.render();
                this.settleOnScreen('approval-failed');
            },
        );
    }

    /** Leave the approve-only flow: reject so the host runs the full ceremony. */
    private finishApproveFallback(): void {
        this.cleanup();
        this.close();
        this.reject?.(new Error('approve-fallback'));
        this.resolve = null;
        this.reject = null;
    }

    private startApprove(): void {
        const flow = this.cfg.approveFlow!;
        this.method = 'wallet';
        this.state = 'approve-waiting';
        this.render();
        flow.run().then(
            () => {
                // The host owns the real result payload; complete() shows the
                // success tile and auto-closes (no trust prompt \u2014 the session
                // already exists and arrived via push).
                this.complete();
            },
            (err: unknown) => {
                // run() may itself decide the approve flow cannot complete
                // (e.g. the pushed approval was never acted on) \u2014 hand the
                // host the fallback instead of a dead-end error tile.
                if ((err as Error)?.message === 'approve-fallback') {
                    this.finishApproveFallback();
                    return;
                }
                this.state = 'error';
                this.errorMsg = (err as Error)?.message ?? 'Approval failed';
                this.render();
            },
        );
    }

    private renderWalletProgress(): HTMLElement {
        return el('div', null,
            el('p', { className: 'scan-hint', style: 'max-width: none; text-align: center;' },
                'Verifying your identity\u2026 This will only take a moment.',
            ),
        );
    }

    private renderPasskeyProgress(): HTMLElement {
        const phase = this.state;
        const label = phase === 'passkey-requesting' ? 'Preparing\u2026' : 'Complete the biometric prompt on your device.';
        return el('div', null,
            el('p', { className: 'scan-hint', style: 'max-width: none; text-align: center;' }, label),
        );
    }

    /** Whether the current state is an in-progress or completed flow state. */
    private isFlowState(): boolean {
        return ['push-waiting', 'qr-scanning', 'wallet-connected', 'authenticating', 'approve-waiting',
                'passkey-requesting', 'passkey-ceremony', 'passkey-verifying', 'success'].includes(this.state);
    }

    /** Renders progress steps in the left brand panel based on current state + method. */
    private renderBrandProgress(): HTMLElement {
        const isSuccess = this.state === 'success';
        const methodLabel = this.methodLabel();

        // Approve-only flow: its own 3-step shape (no QR/notification steps).
        if (this.cfg.approveFlow) {
            const finalStep = this.cfg.approveFlow.reason === 'attributes-widened'
                ? 'Session updated'
                : 'Sealed channel established';
            return el('div', { className: 'brand-progress' },
                el('div', { className: 'steps' },
                    el('div', { className: 'step done' },
                        el('span', { className: 'step-icon' }, '✓'),
                        'Approval requested',
                    ),
                    el('div', { className: `step ${isSuccess ? 'done' : 'active'}` },
                        el('span', { className: 'step-icon' }, isSuccess ? '✓' : '•'),
                        'Approved on your phone',
                    ),
                    el('div', { className: `step ${isSuccess ? 'done' : ''}` },
                        el('span', { className: 'step-icon' }, isSuccess ? '✓' : '•'),
                        finalStep,
                    ),
                ),
            );
        }
        const hasAttestation = this.method === 'wallet' && this.attestation?.valid;
        const methodDetail = this.method === 'passkey'
            ? 'This device'
            : (hasAttestation ? 'Attestation verified' : null);

        let steps: HTMLElement;
        if (this.method === 'passkey') {
            const phase = this.state;
            steps = el('div', { className: 'steps' },
                el('div', { className: `step ${phase !== 'passkey-requesting' ? 'done' : 'active'}` },
                    el('span', { className: 'step-icon' }, phase !== 'passkey-requesting' ? '\u2713' : '\u2022'),
                    'Options received from enclave',
                ),
                el('div', { className: `step ${phase === 'passkey-ceremony' ? 'active' : (phase === 'passkey-verifying' || isSuccess) ? 'done' : ''}` },
                    el('span', { className: 'step-icon' }, (phase === 'passkey-verifying' || isSuccess) ? '\u2713' : '\u2022'),
                    'Biometric prompt completed',
                ),
                el('div', { className: `step ${phase === 'passkey-verifying' ? 'active' : isSuccess ? 'done' : ''}` },
                    el('span', { className: 'step-icon' }, isSuccess ? '\u2713' : '\u2022'),
                    'Enclave verification',
                ),
                el('div', { className: `step ${isSuccess ? 'done' : ''}` },
                    el('span', { className: 'step-icon' }, isSuccess ? '\u2713' : '\u2022'),
                    'Session established',
                ),
            );
        } else {
            // Wallet flow — QR or push
            const viaPush = !!this.cfg.pushToken;
            const isConnected = ['wallet-connected', 'authenticating', 'success'].includes(this.state);
            const isAuth = this.state === 'authenticating' || isSuccess;
            // For push flow: notification is sent as soon as push-waiting starts, so step 1 is done immediately.
            // For QR flow: QR is scanned once wallet connects, so step 1 is done once connected.
            const step1Done = viaPush
                ? ['push-waiting', 'wallet-connected', 'authenticating', 'success'].includes(this.state)
                : isConnected || isAuth;
            const step1Active = !step1Done && this.state === 'qr-scanning';
            const firstLabel = viaPush ? 'Notification sent' : 'QR code scanned';
            const secondLabel = viaPush ? 'Approved on Privasys ID' : 'Server attestation verified';
            const step2Active = viaPush
                ? (this.state === 'push-waiting' || (isConnected && !isAuth))
                : (isConnected && !isAuth);
            steps = el('div', { className: 'steps' },
                el('div', { className: `step ${step1Done ? 'done' : step1Active ? 'active' : ''}` },
                    el('span', { className: 'step-icon' }, step1Done ? '\u2713' : '\u2022'),
                    firstLabel,
                ),
                el('div', { className: `step ${step2Active ? 'active' : isAuth ? 'done' : ''}` },
                    el('span', { className: 'step-icon' }, isAuth ? '\u2713' : '\u2022'),
                    secondLabel,
                ),
                el('div', { className: `step ${this.state === 'authenticating' ? 'active' : isSuccess ? 'done' : ''}` },
                    el('span', { className: 'step-icon' }, isSuccess ? '\u2713' : '\u2022'),
                    'Biometric authentication',
                ),
                el('div', { className: `step ${isSuccess ? 'done' : ''}` },
                    el('span', { className: 'step-icon' }, isSuccess ? '\u2713' : '\u2022'),
                    'Session established',
                ),
            );
        }

        if (isSuccess) {
            steps.appendChild(el('div', { className: 'step done' },
                el('span', { className: 'step-icon' }, '\u2713'),
                `Authenticated via ${methodLabel}`,
            ));
        }

        return el('div', { className: 'brand-progress' },
            steps,
        );
    }

    private renderSuccess(): HTMLElement {
        // Never ask "Trust this device?" when the sign-in itself was a push
        // approval (cfg.pushToken) — the device already behaves as trusted,
        // so the question is contradictory. Only first-time wallet auth
        // (QR) on an untrusted device earns the prompt.
        const showTrust = !this.finished
            && !!this.pushToken && (!this.cfg.deviceTrusted || this.addingDevice) && !this.cfg.pushToken;
        const methodLabel = this.methodLabel();

        return el('div', null,
            // The outcome as a single tile (the progress steps are hidden
            // on success — see stepsUnderway in render()). No attestation
            // badge: the user already saw the verification in the wallet.
            el('div', { className: 'success-icon', html: ICON_CHECK_CIRCLE }),
            el('div', { className: 'success-title' },
                this.cfg.finalScreen ? this.cfg.finalScreen.title
                    : this.cfg.approveFlow ? 'Approved on Privasys ID' : `Authenticated via ${methodLabel}`),
            showTrust ? el('div', { style: 'width: 100%;' },
                el('p', { style: 'font-size: 14px; font-weight: 500; margin-bottom: 6px;' },
                    'Trust this device?',
                ),
                el('p', { className: 'scan-hint', style: 'margin-bottom: 16px; max-width: none;' },
                    'Next time, we\u2019ll send a notification to your phone instead of showing a QR code.',
                ),
                el('button', { className: 'btn-provider primary', onClick: () => {
                    if (this.lookingUp) return;
                    this.lookingUp = true;
                    const stored = this.pushToken ? this.cfg.rememberDevice?.(this.pushToken, this.deviceLabel) : undefined;
                    void Promise.resolve(stored).catch(() => undefined).then(() => {
                        this.lookingUp = false;
                        this.finishWithTrust(true);
                    });
                } },
                    el('span', { html: ICON_SHIELD }),
                    el('span', { className: 'btn-label' }, 'Trust this device'),
                ),
                el('button', {
                    className: 'link-btn',
                    style: 'margin-top: 12px; font-size: 13px; display: block; text-align: center; width: 100%;',
                    onClick: () => this.finishWithTrust(false),
                }, 'Not now'),
            ) : el('div', { className: 'footer' },
                this.cfg.finalScreen
                    ? this.cfg.finalScreen.message
                    : 'Your session is ready. This dialog will close automatically.',
            ),
        );
    }

    /** Refuse the request from the gate, then stay on the outcome. */
    private runDecline(): void {
        const decline = this.cfg.decline;
        if (!decline || this.declining || this.finished) return;
        this.declining = true;
        this.render();
        decline.run().then(
            () => {
                this.cleanup();
                this.declined = true;
                this.finished = true;
                this.state = 'error';
                this.errorMsg = decline.message;
                this.settleOnScreen('declined');
            },
            (err: unknown) => {
                // Usually the request was answered or expired meanwhile.
                this.cleanup();
                this.state = 'error';
                this.finished = true;
                this.errorMsg = `Could not decline: ${(err as Error)?.message || 'the request is no longer open'}`;
                this.settleOnScreen('decline-failed');
            },
        ).finally(() => {
            this.declining = false;
            this.render();
        });
    }

    private renderError(): HTMLElement {
        if (this.declined) {
            return el('div', null,
                el('div', { className: 'error-icon', html: ICON_X_CIRCLE }),
                el('div', { className: 'error-title' }, this.cfg.decline!.title),
                el('div', { className: 'error-msg' }, this.errorMsg),
            );
        }
        // An operation that will not be approved (declined, expired): the
        // outcome is final; whoever started it asks again if it is wanted.
        if (this.cfg.operationApproval) {
            return el('div', null,
                el('div', { className: 'error-icon', html: ICON_X_CIRCLE }),
                el('div', { className: 'error-title' }, 'Approval not completed'),
                el('div', { className: 'error-msg' }, this.errorMsg || 'The approval was not completed.'),
            );
        }
        // Approve-only flow: retry re-sends the push; there is no idle menu
        // to return to (this instance has no ceremony wiring), so the escape
        // hatch hands control back to the host for a full sign-in.
        if (this.cfg.approveFlow) {
            return el('div', null,
                el('div', { className: 'error-icon', html: ICON_X_CIRCLE }),
                el('div', { className: 'error-title' }, 'Approval not completed'),
                el('div', { className: 'error-msg' }, this.errorMsg || 'The approval was not completed in time.'),
                el('button', { className: 'btn-retry', onClick: () => {
                    this.errorMsg = '';
                    this.startApprove();
                } },
                    'Try again',
                ),
                el('button', {
                    className: 'link-btn',
                    style: 'margin-top: 12px; font-size: 13px; display: block; text-align: center; width: 100%;',
                    onClick: () => this.finishApproveFallback(),
                }, 'Sign in another way'),
            );
        }
        return el('div', null,
            el('div', { className: 'error-icon', html: ICON_X_CIRCLE }),
            el('div', { className: 'error-title' }, 'Authentication failed'),
            el('div', { className: 'error-msg' }, this.errorMsg || 'An unknown error occurred.'),
            el('button', { className: 'btn-retry', onClick: () => {
                this.errorMsg = '';
                this.state = 'idle';
                this.render();
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
        this.startCompleteWatch();

        // Pass the OIDC session_id through to the broker so the wallet uses
        // it as `?session_id=` on /fido2/authenticate/begin. That is what the
        // IdP FIDO2 handler stores against the challenge entry — without it,
        // the handler can't link the assertion back to the OIDC session and
        // /session/complete falls through with no real user_id.
        client.notifyAndWait(this.cfg.pushToken!, this.cfg.sessionId, this.cfg.sessionRelay).then(
            (result) => {
                this.sessionToken = result.sessionToken;
                this.attestation = result.attestation;
                this.sessionId = result.sessionId;
                // The wallet reached by this push: its answer may come before
                // it has loaded its own push token.
                this.pushToken = result.pushToken || this.cfg.pushToken;
                this.deviceLabel = result.deviceLabel;
                this.attributes = result.attributes;
                this.sessionRelay = result.sessionRelay;
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
        const { sessionId, payload } = client.createQR(this.cfg.sessionId, this.cfg.sessionRelay);
        this.sessionId = sessionId;
        this.qrPayload = payload;
        this.state = 'qr-scanning';
        this.render();
        this.startCompleteWatch();

        client.waitForResult(sessionId).then(
            (result) => {
                this.sessionToken = result.sessionToken;
                this.attestation = result.attestation;
                this.sessionId = result.sessionId;
                this.pushToken = result.pushToken;
                this.deviceLabel = result.deviceLabel;
                this.attributes = result.attributes;
                this.sessionRelay = result.sessionRelay;
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
                    // If no credentials found or user dismissed an empty picker,
                    // automatically try registration to create a new passkey.
                    const msg = authErr?.message ?? '';
                    if (msg.includes('no credentials') || msg.includes('not found') || msg.includes('cancelled')) {
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

    private async startSocial(provider: string, own = false): Promise<void> {
        if (!this.cfg.onSocialAuth) return;
        this.method = 'social';
        this.socialName = this.cfg.socialDisplayNames?.[provider]
            ?? (own ? this.cfg.socialOwn?.find((o) => o.provider === provider)?.displayName : undefined)
            ?? providerName(provider);
        this.state = 'authenticating';
        this.render();
        try {
            await this.cfg.onSocialAuth(provider, own);
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

        // First-time wallet auth (QR) on an untrusted device: wait for the
        // user to answer the trust prompt. Everything else auto-closes: no
        // push token, already trusted, or the ceremony itself ran over a
        // push notification (cfg.pushToken) — the latter counts as trust,
        // so the device hint is (re)saved.
        // A headless gate never asks: the person cannot see the question.
        const end = finishOnSuccess({
            pushToken: this.pushToken,
            deviceTrusted: this.cfg.deviceTrusted && !this.addingDevice,
            viaPush: !!this.cfg.pushToken,
            headless: this.cfg.headless,
        });
        if (end.now) {
            setTimeout(() => this.finishWithTrust(end.trust), 1200);
        }
    }

    private finishWithTrust(trust: boolean): void {
        const result: SignInResult = {
            sessionToken: this.sessionToken,
            method: this.method,
            attestation: this.attestation,
            sessionId: this.sessionId,
            pushToken: this.pushToken,
            deviceLabel: this.deviceLabel,
            attributes: this.attributes,
            trustDevice: trust,
            sessionRelay: this.sessionRelay,
            ...(this.viaPoll ? { completedViaPoll: true } : {}),
        };
        if (this.cfg.finalScreen) {
            // The outcome stays on screen; the trust question, if it was
            // asked, has been answered.
            this.finished = true;
            this.render();
        } else {
            this.close();
        }
        this.resolve?.(result);
        this.resolve = null;
        this.reject = null;
    }

    /** End the flow with an outcome that stays on screen: the caller's
     *  promise rejects with `code`, and the gate keeps showing why. */
    private settleOnScreen(code: string): void {
        this.reject?.(new Error(code));
        this.resolve = null;
        this.reject = null;
    }

    private handleCancel(): void {
        this.cleanup();
        this.close();
        this.reject?.(new Error('Authentication cancelled'));
        this.resolve = null;
        this.reject = null;
    }

    private cleanup(): void {
        this.stopCompleteWatch();
        if (this.relayClient) {
            this.relayClient.destroy();
            this.relayClient = null;
        }
    }

    // ---- same-device completion watcher ----

    /** Poll the IdP session status while a wallet flow is pending, so the
     *  ceremony completes even when the broker relay died during the
     *  same-device app switch. Fires immediately on tab re-focus. */
    private startCompleteWatch(): void {
        if (!this.cfg.checkComplete || this.completeWatch) return;
        let inFlight = false;
        const check = async (): Promise<void> => {
            if (inFlight) return;
            if (!['qr-scanning', 'push-waiting', 'wallet-connected', 'authenticating'].includes(this.state)) return;
            inFlight = true;
            try {
                if (await this.cfg.checkComplete!()) {
                    this.stopCompleteWatch();
                    // The relay may be dead; the IdP session is the truth.
                    // Tear the relay down and complete from server state.
                    if (this.relayClient) {
                        this.relayClient.destroy();
                        this.relayClient = null;
                    }
                    this.method = 'wallet';
                    this.viaPoll = true;
                    this.complete();
                }
            } catch { /* transient poll failure — next tick retries */ }
            finally { inFlight = false; }
        };
        const timer = setInterval(() => void check(), 3000);
        const onVis = (): void => {
            if (document.visibilityState === 'visible') void check();
        };
        document.addEventListener('visibilitychange', onVis);
        this.completeWatch = { timer, onVis };
    }

    private stopCompleteWatch(): void {
        if (!this.completeWatch) return;
        clearInterval(this.completeWatch.timer);
        document.removeEventListener('visibilitychange', this.completeWatch.onVis);
        this.completeWatch = null;
    }

    /** After the handoff tap: if the page is still visible shortly after,
     *  the app switch did not happen — the wallet is most likely not
     *  installed. Surface the install/cross-device paths prominently. */
    private watchWalletOpen(): void {
        setTimeout(() => {
            if (document.visibilityState === 'visible'
                && this.state === 'qr-scanning'
                && !this.showQrOnMobile
                && !this.walletOpenFailed) {
                this.walletOpenFailed = true;
                this.render();
            }
        }, 2000);
    }

    // ---- client accessors ----

    private getRelayClient(): PrivasysAuth {
        if (!this.relayClient) {
            this.relayClient = new PrivasysAuth({
                rpId: this.rpId,
                brokerUrl: this.cfg.brokerUrl,
                timeout: this.cfg.timeout,
                requestedAttributes: this.cfg.requestedAttributes,
                attributeRequirements: this.cfg.attributeRequirements,
                disclosureVouchers: this.cfg.disclosureVouchers,
                appName: this.cfg.appName,
                privacyPolicyUrl: this.cfg.privacyPolicyUrl,
                clientId: this.cfg.clientId,
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
                sessionId: this.cfg.sessionId,
                fido2Base: this.cfg.fido2Base ?? `${globalThis.location.origin}/fido2`,
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
