// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Channels to enclave apps: sealed (the session keys live in the persistent
 * frame, which this page drives over postMessage) or direct (HTTPS to the
 * app's host with an audience token). One channel per host; its transport
 * is swapped underneath when it is re-established.
 */

import { DirectWebSocket, headerRecord, sendDirect } from '../direct-request';
import { cloneableInit } from './session';
import type { SessionFrame } from './session-frame';
import type { AppChannel, AppResponse, AppStreamResponse, AppWebSocket } from './types';

type ChannelState = AppChannel['state'];

/** One way of reaching an app. */
interface Transport {
    readonly kind: 'sealed' | 'direct';
    request(method: string, path: string, body?: unknown, init?: RequestInit): Promise<AppResponse>;
    stream(method: string, path: string, body?: unknown, init?: RequestInit): Promise<AppStreamResponse>;
    openWebSocket(path: string): AppWebSocket;
}

/** The channel to one host, as the page holds it. */
export class Channel implements AppChannel {
    private impl: Transport | null = null;
    private _state: ChannelState = 'signed-out';
    private readonly stateCbs = new Set<(s: ChannelState) => void>();
    /** The audience of a direct channel, kept from the first app() that named it. */
    audience: string | undefined;

    constructor(readonly host: string) {}

    get transport(): 'sealed' | 'direct' {
        return this.impl?.kind ?? 'sealed';
    }

    get state(): ChannelState {
        return this._state;
    }

    /** Whether the channel works as it is, over `kind`. */
    live(kind: 'sealed' | 'direct'): boolean {
        return !!this.impl && this.impl.kind === kind && this._state !== 'signed-out';
    }

    use(impl: Transport): void {
        this.impl = impl;
        this.setState('ok');
    }

    setState(state: ChannelState): void {
        if (state === this._state) return;
        this._state = state;
        for (const cb of this.stateCbs) {
            try { cb(state); } catch { /* isolate listener errors */ }
        }
    }

    onState(cb: (state: ChannelState) => void): () => void {
        this.stateCbs.add(cb);
        return () => this.stateCbs.delete(cb);
    }

    private current(): Transport {
        if (!this.impl || this._state === 'signed-out') {
            throw new Error(`AuthFrame: the channel to ${this.host} is closed; call app() again`);
        }
        return this.impl;
    }

    async request(method: string, path: string, body?: unknown, init?: RequestInit): Promise<AppResponse> {
        return this.current().request(method, path, body, init);
    }

    async stream(method: string, path: string, body?: unknown, init?: RequestInit): Promise<AppStreamResponse> {
        return this.current().stream(method, path, body, init);
    }

    async openWebSocket(path: string): Promise<AppWebSocket> {
        return this.current().openWebSocket(path);
    }
}

/** A direct channel: HTTPS to `https://<host>` with a token for `audience`. */
export function directTransport(host: string, token: () => Promise<string>): Transport {
    const origin = `https://${host}`;
    const send = async (method: string, path: string, body: unknown, init?: RequestInit) =>
        sendDirect({ origin, token: await token(), method, path, body, init });
    return {
        kind: 'direct',
        async request(method, path, body, init) {
            const resp = await send(method, path, body, init);
            return {
                status: resp.status,
                headers: headerRecord(resp.headers),
                body: new Uint8Array(await resp.arrayBuffer()),
                transport: 'direct',
            };
        },
        async stream(method, path, body, init) {
            const resp = await send(method, path, body, init);
            return {
                status: resp.status,
                headers: headerRecord(resp.headers),
                body: resp.body ?? new ReadableStream<Uint8Array>({ start: (c) => c.close() }),
                transport: 'direct',
            };
        },
        openWebSocket(path) {
            return new DirectWebSocket(origin, path, token);
        },
    };
}

/**
 * The page's half of a sealed WebSocket that runs in the persistent frame:
 * `send` and `close` are posted to the frame, and the frame's events are
 * dispatched here by {@link SealedBridge}.
 */
class BridgedSocket implements AppWebSocket {
    readonly ready: Promise<void>;
    private resolveReady!: () => void;
    private rejectReady!: (e: Error) => void;
    private readyPending = true;
    private isOpen = false;
    private closedLocally = false;
    private readonly msgCbs = new Set<(d: Uint8Array) => void>();
    private readonly closeCbs = new Set<(i: { code: number; reason: string; wasClean: boolean }) => void>();
    private readonly errCbs = new Set<(e: Error) => void>();

    constructor(private readonly post: (msg: Record<string, unknown>) => void) {
        this.ready = new Promise<void>((resolve, reject) => {
            this.resolveReady = resolve;
            this.rejectReady = reject;
        });
        // A rejected `ready` nobody awaits must not surface as unhandled.
        this.ready.catch(() => undefined);
    }

    get open(): boolean {
        return this.isOpen && !this.closedLocally;
    }

    send(data: Uint8Array | ArrayBuffer | string | object): void {
        if (this.closedLocally) throw new Error('sealed websocket is closed');
        this.post({ type: 'privasys:session:ws-send', data });
    }
    onMessage(cb: (d: Uint8Array) => void): () => void {
        this.msgCbs.add(cb);
        return () => this.msgCbs.delete(cb);
    }
    onClose(cb: (i: { code: number; reason: string; wasClean: boolean }) => void): void {
        this.closeCbs.add(cb);
    }
    onError(cb: (e: Error) => void): void {
        this.errCbs.add(cb);
    }
    close(code = 1000, reason = ''): void {
        this.closedLocally = true;
        if (this.readyPending) {
            this.readyPending = false;
            this.rejectReady(new Error('sealed websocket closed by caller'));
        }
        this.post({ type: 'privasys:session:ws-close', code, reason });
    }

    opened(): void {
        this.isOpen = true;
        if (this.readyPending) {
            this.readyPending = false;
            this.resolveReady();
        }
    }
    message(d: Uint8Array): void {
        for (const cb of this.msgCbs) {
            try { cb(d); } catch { /* isolate listener errors */ }
        }
    }
    error(e: Error): void {
        for (const cb of this.errCbs) {
            try { cb(e); } catch { /* isolate */ }
        }
    }
    closed(i: { code: number; reason: string; wasClean: boolean }): void {
        this.isOpen = false;
        if (this.readyPending) {
            this.readyPending = false;
            this.rejectReady(new Error(`sealed websocket closed before open (code ${i.code})`));
        }
        for (const cb of this.closeCbs) {
            try { cb(i); } catch { /* isolate */ }
        }
    }
}

interface StreamSlot {
    host: string;
    controller?: ReadableStreamDefaultController<Uint8Array>;
    resolve?: (r: AppStreamResponse) => void;
    reject?: (e: Error) => void;
}

/**
 * The page's side of every sealed channel of one persistent frame: the
 * requests, streams and sockets in flight, by id, and the frame's events
 * for them.
 */
export class SealedBridge {
    private seq = 0;
    private readonly streams = new Map<number, StreamSlot>();
    private readonly sockets = new Map<number, BridgedSocket>();

    constructor(private readonly frame: SessionFrame) {}

    /** The sealed transport of `host`. */
    transport(host: string): Transport {
        const frame = this.frame;
        return {
            kind: 'sealed',
            request: async (method, path, body, init) => {
                const r = await frame.call(
                    { type: 'privasys:session:request', host, method, path, body, init: cloneableInit(init) },
                    'privasys:session:response',
                    0,
                );
                if (typeof r.error === 'string') throw new Error(r.error);
                return {
                    status: r.status as number,
                    headers: (r.headers as Record<string, string>) || {},
                    body: r.body as Uint8Array,
                    transport: 'sealed',
                };
            },
            stream: (method, path, body, init) => this.stream(host, method, path, body, init),
            openWebSocket: (path) => {
                const id = ++this.seq;
                const socket = new BridgedSocket((msg) => { void frame.post({ ...msg, id, host }); });
                this.sockets.set(id, socket);
                void frame.post({ type: 'privasys:session:ws-open', id, host, path });
                return socket;
            },
        };
    }

    private stream(host: string, method: string, path: string, body: unknown, init?: RequestInit): Promise<AppStreamResponse> {
        const id = ++this.seq;
        const signal = init?.signal;
        return new Promise<AppStreamResponse>((resolve, reject) => {
            this.streams.set(id, { host, resolve, reject });
            // The signal cannot cross postMessage: an abort is sent as a
            // cancel, and fails the stream here.
            if (signal) {
                const onAbort = (): void => {
                    void this.frame.post({ type: 'privasys:session:stream-cancel', id, host });
                    const slot = this.streams.get(id);
                    const err = new DOMException('Aborted', 'AbortError');
                    if (slot?.reject) slot.reject(err);
                    else try { slot?.controller?.error(err); } catch { /* closed */ }
                    this.streams.delete(id);
                };
                if (signal.aborted) queueMicrotask(onAbort);
                else signal.addEventListener('abort', onAbort, { once: true });
            }
            void this.frame.post({
                type: 'privasys:session:stream-request', id, host, method, path, body, init: cloneableInit(init),
            });
        });
    }

    /** Handle one of the frame's events; true when it was a sealed one. */
    handle(data: Record<string, unknown>): boolean {
        const id = data.id as number;
        switch (data.type) {
            case 'privasys:session:stream-start': {
                const slot = this.streams.get(id);
                if (!slot?.resolve) return true;
                // Stopping the body stops the stream in the frame.
                const body = new ReadableStream<Uint8Array>({
                    start: (c) => { slot.controller = c; },
                    cancel: () => {
                        this.streams.delete(id);
                        void this.frame.post({ type: 'privasys:session:stream-cancel', id, host: slot.host });
                    },
                });
                slot.resolve({
                    status: data.status as number,
                    headers: (data.headers as Record<string, string>) || {},
                    body,
                    transport: 'sealed',
                });
                slot.resolve = undefined;
                slot.reject = undefined;
                return true;
            }
            case 'privasys:session:stream-chunk': {
                const chunk = data.chunk as Uint8Array;
                const slot = this.streams.get(id);
                if (slot?.controller && chunk && chunk.byteLength > 0) {
                    slot.controller.enqueue(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
                }
                return true;
            }
            case 'privasys:session:stream-end': {
                this.streams.get(id)?.controller?.close();
                this.streams.delete(id);
                return true;
            }
            case 'privasys:session:stream-error': {
                const slot = this.streams.get(id);
                const err = new Error(String(data.error || 'sealed stream failed'));
                if (slot?.reject) slot.reject(err);
                else slot?.controller?.error(err);
                this.streams.delete(id);
                return true;
            }
            case 'privasys:session:ws-open-ack':
                this.sockets.get(id)?.opened();
                return true;
            case 'privasys:session:ws-message':
                this.sockets.get(id)?.message(data.data as Uint8Array);
                return true;
            case 'privasys:session:ws-error':
                this.sockets.get(id)?.error(new Error(String(data.error || 'sealed websocket error')));
                return true;
            case 'privasys:session:ws-close':
                this.sockets.get(id)?.closed({
                    code: typeof data.code === 'number' ? data.code : 1006,
                    reason: String(data.reason ?? ''),
                    wasClean: Boolean(data.wasClean),
                });
                this.sockets.delete(id);
                return true;
            default:
                return false;
        }
    }

    /** Fail everything in flight: the frame is gone. */
    close(): void {
        const err = new Error('AuthFrame destroyed');
        for (const slot of this.streams.values()) {
            if (slot.reject) slot.reject(err);
            else try { slot.controller?.error(err); } catch { /* closed */ }
        }
        this.streams.clear();
        for (const s of this.sockets.values()) s.closed({ code: 1006, reason: 'AuthFrame destroyed', wasClean: false });
        this.sockets.clear();
    }
}
