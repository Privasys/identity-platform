// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The persistent frame: one hidden iframe per {@link AuthFrame} on the
 * identity provider's origin. It holds the session's renewal, mints tokens,
 * reports every change to the session (from any tab of the site), and
 * carries every sealed channel. It stays mounted while the page is signed
 * out, to hear of a sign-in from another tab.
 */

const HIDDEN = 'position:fixed;width:0;height:0;border:none;opacity:0;pointer-events:none;';

interface PendingCall {
    responseType: string;
    resolve: (data: Record<string, unknown>) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout> | undefined;
}

export class SessionFrame {
    private iframe: HTMLIFrameElement | null = null;
    private ready: Promise<void> | null = null;
    private readonly calls = new Map<string, PendingCall>();
    private seq = 0;
    // A refresh grant runs in the frame: removing it now would lose the
    // rotated token, so teardown waits for it.
    private renewalInFlight = false;
    private readonly handler = (e: MessageEvent): void => {
        if (e.origin !== this.authOrigin || !this.iframe || e.source !== this.iframe.contentWindow) return;
        const data = e.data as Record<string, unknown> | null;
        if (!data || typeof data.type !== 'string') return;
        if (data.type === 'privasys:ready') {
            this.markReady?.();
            return;
        }
        if (data.type === 'privasys:renewal') {
            this.renewalInFlight = data.phase === 'start';
            return;
        }
        const id = typeof data.id === 'string' ? data.id : null;
        const call = id ? this.calls.get(id) : undefined;
        if (call && call.responseType === data.type) {
            this.calls.delete(id!);
            clearTimeout(call.timer);
            call.resolve(data);
            return;
        }
        this.onEvent(data);
    };
    private markReady: (() => void) | null = null;

    constructor(
        private readonly authOrigin: string,
        /** Every message the frame sends that is not the answer to a call. */
        private readonly onEvent: (data: Record<string, unknown>) => void,
    ) {}

    /** Mount the frame (once) and resolve when it can take messages. */
    mount(): Promise<void> {
        if (this.ready) return this.ready;
        const iframe = document.createElement('iframe');
        iframe.src = this.authOrigin + '/auth/';
        iframe.style.cssText = HIDDEN;
        this.iframe = iframe;
        window.addEventListener('message', this.handler);
        this.ready = new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => {
                this.markReady = null;
                this.teardown();
                this.ready = null;
                reject(new Error('the sign-in frame did not load'));
            }, 15_000);
            this.markReady = () => {
                clearTimeout(timer);
                this.markReady = null;
                resolve();
            };
        });
        document.body.appendChild(iframe);
        return this.ready;
    }

    /** Post a message to the frame (mounted). */
    async post(msg: Record<string, unknown>): Promise<void> {
        await this.mount();
        this.iframe?.contentWindow?.postMessage(msg, this.authOrigin);
    }

    /** Post a message that names an id, and resolve with the frame's answer
     *  of `responseType`, within `timeoutMs` (0: no limit). */
    async call(msg: Record<string, unknown>, responseType: string, timeoutMs: number): Promise<Record<string, unknown>> {
        await this.mount();
        const id = `c${++this.seq}`;
        return new Promise((resolve, reject) => {
            const timer = timeoutMs > 0
                ? setTimeout(() => {
                    this.calls.delete(id);
                    reject(new Error('timeout'));
                }, timeoutMs)
                : undefined;
            this.calls.set(id, { responseType, resolve, reject, timer });
            this.iframe?.contentWindow?.postMessage({ ...msg, id }, this.authOrigin);
        });
    }

    /** Remove the frame, after a refresh grant in flight has stored its token. */
    destroy(): void {
        const err = new Error('AuthFrame destroyed');
        for (const c of this.calls.values()) {
            clearTimeout(c.timer);
            c.reject(err);
        }
        this.calls.clear();
        if (!this.renewalInFlight) {
            this.teardown();
            return;
        }
        const deadline = Date.now() + 10_000;
        const tick = (): void => {
            if (!this.renewalInFlight || Date.now() > deadline) this.teardown();
            else setTimeout(tick, 100);
        };
        setTimeout(tick, 100);
    }

    private teardown(): void {
        window.removeEventListener('message', this.handler);
        this.iframe?.remove();
        this.iframe = null;
    }
}
