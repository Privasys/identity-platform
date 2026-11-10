/**
 * A request to an app's private route over its direct name.
 *
 * The person signed in without the wallet, so there is no sealed session: the
 * request goes over ordinary HTTPS to the app's direct name, where TLS ends in
 * the enclave, and carries an access token minted for the app. The runtime
 * checks the token, removes it and gives the app the same identity headers as
 * a sealed request. The body is encoded the way a sealed request encodes it,
 * so an app route reads the same bytes whichever way they came.
 */

import type { SealedWebSocket } from './enclave-session';

/** Which way {@link AuthFrame.request} sent a request. */
export type AppTransport = 'sealed' | 'direct';

export interface DirectRequest {
    /** The app's direct origin, `https://<direct name>`. */
    origin: string;
    /** An access token whose audience is the app. */
    token: string;
    method: string;
    path: string;
    body?: unknown;
    init?: RequestInit;
    fetchImpl?: typeof fetch;
}

/**
 * The URL for `path` on `origin`. Refuses anything that would leave the
 * origin, such as an absolute URL or `//host`, because the request carries
 * the person's token.
 */
export function directUrl(origin: string, path: string): string {
    if (!path.startsWith('/')) throw new Error('AuthFrame: the path must start with "/"');
    const base = new URL(origin);
    if (base.protocol !== 'https:') throw new Error('AuthFrame: the direct origin must be https');
    const url = new URL(path, base);
    if (url.origin !== base.origin) throw new Error('AuthFrame: the path must stay on the direct origin');
    return url.toString();
}

/** The body as a sealed request would encode it, and its content type. */
export function directBody(body: unknown): { bytes?: Uint8Array; contentType?: string } {
    if (body == null) return {};
    if (body instanceof Uint8Array) return { bytes: body };
    if (body instanceof ArrayBuffer) return { bytes: new Uint8Array(body) };
    if (typeof body === 'string') return { bytes: new TextEncoder().encode(body) };
    return { bytes: new TextEncoder().encode(JSON.stringify(body)), contentType: 'application/json' };
}

/** Send the request; the caller reads the response. */
export async function sendDirect(req: DirectRequest): Promise<Response> {
    const method = req.method.toUpperCase();
    const headers = new Headers(req.init?.headers);
    headers.set('Authorization', `Bearer ${req.token}`);
    const bodyless = method === 'GET' || method === 'HEAD';
    const { bytes, contentType } = bodyless ? {} : directBody(req.body);
    if (contentType && !headers.has('Content-Type')) headers.set('Content-Type', contentType);
    const fetchImpl = req.fetchImpl ?? fetch;
    return fetchImpl(directUrl(req.origin, req.path), {
        ...req.init,
        method,
        headers,
        // The token never goes to another origin, and no cookie rides along.
        credentials: 'omit',
        redirect: 'error',
        ...(bytes ? { body: bytes as BodyInit } : {}),
    });
}

/** Response headers as a plain record, the shape a sealed response has. */
export function headerRecord(headers: Headers): Record<string, string> {
    const out: Record<string, string> = {};
    headers.forEach((v, k) => { out[k] = v; });
    return out;
}

/**
 * The subprotocols that carry the token on a direct WebSocket. A browser
 * cannot set a header on a WebSocket, so the runtime reads the token from
 * here, takes both out before the app sees the request, and answers
 * {@link DIRECT_WS_PROTOCOL} on the handshake.
 */
export const DIRECT_WS_PROTOCOL = 'privasys.v1';
export const DIRECT_WS_BEARER_PREFIX = 'privasys.bearer.';

/**
 * A WebSocket to an app's private route over its direct name, with the same
 * interface as a sealed one: messages go out as binary frames encoded the way
 * a sealed socket encodes them, and come in as bytes. The runtime closes the
 * socket when its token expires; open a new one then, as after any close.
 */
export class DirectWebSocket implements SealedWebSocket {
    readonly ready: Promise<void>;
    private resolveReady!: () => void;
    private rejectReady!: (e: Error) => void;
    private ws: WebSocket | null = null;
    private queue: Uint8Array[] = [];
    private closedLocally = false;
    private readonly messageCbs = new Set<(d: Uint8Array) => void>();
    private readonly closeCbs: Array<(i: { code: number; reason: string; wasClean: boolean }) => void> = [];
    private readonly errorCbs: Array<(e: Error) => void> = [];

    constructor(origin: string, path: string, token: () => Promise<string>, makeSocket: (url: string, protocols: string[]) => WebSocket = (u, p) => new WebSocket(u, p)) {
        this.ready = new Promise((resolve, reject) => { this.resolveReady = resolve; this.rejectReady = reject; });
        // A caller that never awaits ready must not see an unhandled rejection.
        this.ready.catch(() => {});
        let url: string;
        try {
            url = directUrl(origin, path).replace(/^https:/, 'wss:');
        } catch (err) {
            this.fail(err as Error);
            return;
        }
        token().then((t) => {
            if (this.closedLocally) return;
            this.attach(makeSocket(url, [DIRECT_WS_PROTOCOL, DIRECT_WS_BEARER_PREFIX + t]));
        }, (err) => this.fail(err as Error));
    }

    get open(): boolean {
        return !!this.ws && this.ws.readyState === 1 && !this.closedLocally;
    }

    private attach(ws: WebSocket): void {
        this.ws = ws;
        ws.binaryType = 'arraybuffer';
        ws.onopen = () => {
            for (const m of this.queue) ws.send(m);
            this.queue = [];
            this.resolveReady();
        };
        ws.onmessage = (ev: MessageEvent) => {
            const d = typeof ev.data === 'string' ? new TextEncoder().encode(ev.data) : new Uint8Array(ev.data as ArrayBuffer);
            for (const cb of this.messageCbs) {
                try { cb(d); } catch { /* isolate listener errors */ }
            }
        };
        ws.onerror = () => this.emitError(new Error('direct websocket error'));
        ws.onclose = (ev: CloseEvent) => {
            this.rejectReady(new Error(`direct websocket closed before open (code ${ev.code})`));
            for (const cb of this.closeCbs) {
                try { cb({ code: ev.code, reason: ev.reason, wasClean: ev.wasClean }); } catch { /* isolate */ }
            }
        };
    }

    private fail(err: Error): void {
        this.rejectReady(err);
        this.emitError(err);
        for (const cb of this.closeCbs) {
            try { cb({ code: 1006, reason: err.message, wasClean: false }); } catch { /* isolate */ }
        }
    }

    private emitError(err: Error): void {
        for (const cb of this.errorCbs) {
            try { cb(err); } catch { /* isolate */ }
        }
    }

    send(data: Uint8Array | ArrayBuffer | string | object): void {
        if (this.closedLocally) throw new Error('direct websocket is closed');
        const bytes = directBody(data).bytes ?? new Uint8Array(0);
        if (this.open) this.ws!.send(bytes);
        else this.queue.push(bytes);
    }

    onMessage(cb: (data: Uint8Array) => void): () => void {
        this.messageCbs.add(cb);
        return () => this.messageCbs.delete(cb);
    }

    onClose(cb: (info: { code: number; reason: string; wasClean: boolean }) => void): void {
        this.closeCbs.push(cb);
    }

    onError(cb: (err: Error) => void): void {
        this.errorCbs.push(cb);
    }

    close(code = 1000, reason = ''): void {
        if (this.closedLocally) return;
        this.closedLocally = true;
        this.queue = [];
        if (this.ws) this.ws.close(code, reason);
        else this.rejectReady(new Error('direct websocket closed by caller'));
    }
}
