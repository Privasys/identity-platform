// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The visible gate: an iframe on the identity provider's origin that runs one
 * ceremony (a sign-in, a link, an approval) and reports how it ended. It
 * exists only for the ceremony.
 */

import { FRAME_PATH } from './frame-path';
import { FRAME_SIZE_MESSAGE, inlineFrameHeight } from '../frame-size';
import { sanitiseGateState, type GateChoice, type GateOptions } from '../gate-headless';
import { InsufficientCreditsError, type GateOutcome, type HeadlessGate } from './types';

/** How a ceremony ended, as the frame reports it. */
export interface GateResult {
    accessToken?: string;
    method?: 'wallet' | 'passkey' | 'social';
    /** The enclave hosts the wallet approved within the sign-in, and how
     *  long their vouchers may take to land. */
    apps?: { hosts: string[]; waitMs: number };
    /** An identity provider approval: approved, or how it ended without. */
    approved?: boolean;
    outcome?: GateOutcome;
    /** A link: the ID token for the page's server. */
    linked?: boolean;
    idToken?: string;
}

export interface GateRun {
    done: Promise<GateResult>;
    cancel: () => void;
}

const HIDDEN = 'position:fixed;width:0;height:0;border:none;opacity:0;pointer-events:none;';
const ALLOW = 'publickey-credentials-get *; publickey-credentials-create *';

/**
 * Open the gate and run one ceremony. `config` is sent to the frame as the
 * ceremony's configuration. An approval or outcome leaves the gate on
 * screen, saying how it ended; anything else removes it.
 */
export function openGate(opts: {
    authOrigin: string;
    /** Path of the frame page on the identity provider (default FRAME_PATH). */
    framePath?: string;
    config: Record<string, unknown>;
    container: HTMLElement | null;
    headless?: HeadlessGate | null;
    onPasskey?: () => void;
}): GateRun {
    const { authOrigin, container } = opts;
    const frameUrl = authOrigin + (opts.framePath ?? FRAME_PATH);
    const headless = opts.headless ?? null;
    const iframe = document.createElement('iframe');
    iframe.src = frameUrl;
    iframe.allow = ALLOW;
    if (headless) {
        iframe.style.cssText = HIDDEN;
        document.body.appendChild(iframe);
    } else if (container) {
        iframe.style.cssText = 'width:100%;height:100%;border:none;display:block;';
        container.appendChild(iframe);
    } else {
        iframe.style.cssText = 'position:fixed;inset:0;width:100%;height:100%;z-index:999999;border:none;background:#fff;';
        document.body.appendChild(iframe);
    }

    let settle: { resolve: (r: GateResult) => void; reject: (e: Error) => void } | null = null;
    const done = new Promise<GateResult>((resolve, reject) => { settle = { resolve, reject }; });
    const post = (msg: Record<string, unknown>): void => {
        iframe.contentWindow?.postMessage(msg, authOrigin);
    };
    const stop = (): void => {
        window.removeEventListener('message', handler);
        settle = null;
    };
    const remove = (): void => {
        stop();
        iframe.remove();
    };
    const fail = (err: Error): void => {
        const s = settle;
        remove();
        s?.reject(err);
    };

    // Headless: the page holds the click's activation, so it opens the
    // popups the frame names; only the identity provider's own sign-in and
    // device addresses are ever opened.
    const openPopup = (id: string, url: string): void => {
        const reply = (ok: boolean, error?: string): void =>
            post({ type: 'privasys:gate:popup-result', id, ok, ...(error ? { error } : {}) });
        const place = (w: number, h: number) =>
            `width=${w},height=${h},left=${window.screenX + (window.innerWidth - w) / 2},top=${window.screenY + (window.innerHeight - h) / 2}`;
        if (url === `${frameUrl}#device`) {
            // The frame's lookup of a phone this browser knows: the popup
            // talks to the frame and closes itself.
            reply(!!window.open(url, 'privasys-device', place(420, 240)));
            return;
        }
        if (!url.startsWith(`${authOrigin}/auth/social?`)) {
            reply(false, 'Refused sign-in address');
            return;
        }
        const popup = window.open(url, 'privasys-social', place(500, 650));
        if (!popup) {
            reply(false, 'Popup blocked: please allow popups for this site');
            return;
        }
        const end = (ok: boolean, error?: string): void => {
            window.removeEventListener('message', onPopup);
            clearInterval(poll);
            try { popup.close(); } catch { /* already closed */ }
            reply(ok, error);
        };
        const onPopup = (ev: MessageEvent): void => {
            if (ev.source !== popup || ev.origin !== authOrigin) return;
            if (ev.data?.type === 'privasys:social-complete') end(true);
            else if (ev.data?.type === 'privasys:social-error') end(false, String(ev.data.error || 'Social authentication failed'));
        };
        window.addEventListener('message', onPopup);
        const poll = setInterval(() => { if (popup.closed) end(false, 'Authentication cancelled'); }, 500);
    };

    const handler = (e: MessageEvent): void => {
        if (e.origin !== authOrigin || e.source !== iframe.contentWindow) return;
        const data = e.data;
        if (!data || typeof data.type !== 'string') return;
        switch (data.type) {
            case 'privasys:ready':
                post({
                    type: 'privasys:init',
                    config: {
                        ...opts.config,
                        ...(headless ? { headless: true } : {}),
                        caps: ['parent-navigate', ...(headless ? ['headless'] : [])],
                    },
                });
                break;
            case 'privasys:result': {
                const result = (data.result ?? {}) as GateResult;
                const s = settle;
                // An approval's gate stays on its outcome, in the page that holds it.
                if (result.approved || result.outcome) stop();
                else remove();
                s?.resolve(result);
                break;
            }
            case 'privasys:cancel':
                fail(new Error('Authentication cancelled'));
                break;
            case 'privasys:error':
                fail(data.errorCode === 'insufficient_credits'
                    ? new InsufficientCreditsError(data.error)
                    : new Error(data.error || 'Authentication failed'));
                break;
            case 'privasys:gate': {
                if (!headless || !data.options || typeof data.options !== 'object') break;
                headless.onOptions(data.options as GateOptions, {
                    start: (choice: GateChoice) => post({ type: 'privasys:gate:start', choice }),
                    cancel: () => fail(new Error('Authentication cancelled')),
                });
                break;
            }
            case 'privasys:gate:state': {
                const state = sanitiseGateState(data);
                if (headless && state) headless.onState?.(state);
                break;
            }
            case 'privasys:gate:popup':
                if (headless) openPopup(String(data.id || ''), String(data.url || ''));
                break;
            case 'privasys:navigate': {
                // The wallet handoff on a phone must be a top-level,
                // first-party navigation: WebKit blocks a custom scheme from
                // a cross-origin frame. The tap in the frame gives this page
                // the activation, and the page does not unload.
                const url = String(data.url || '');
                if (/^privasys-wallet(-dev|-preview)?:\/\//.test(url)) window.location.href = url;
                break;
            }
            case FRAME_SIZE_MESSAGE: {
                // An inline gate is as tall as its content; a modal fills the
                // viewport and a headless one stays 0x0.
                if (headless || !container) break;
                const h = inlineFrameHeight(data.height);
                if (h !== null) iframe.style.height = `${h}px`;
                break;
            }
            case 'privasys:operation:passkey':
                opts.onPasskey?.();
                break;
        }
    };
    window.addEventListener('message', handler);

    return { done, cancel: () => fail(new Error('Authentication cancelled')) };
}
