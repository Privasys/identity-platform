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
