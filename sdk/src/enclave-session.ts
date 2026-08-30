// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * PrivasysSession — browser-side session-relay client.
 *
 * Lets a browser SDK reach an enclave app through a TLS-terminating gateway
 * while keeping the request/response body confidential to the enclave.
 *
 * Flow:
 *   1. Generate ephemeral P-256 keypair via WebCrypto.
 *   2. Pass `sdk_pub` (SEC1 uncompressed, base64url) to the wallet, which
 *      attests the enclave end-to-end and brings back `{enc_pub, session_id,
 *      app_envelope}` plus a wallet signature binding the session to a
 *      proven enclave identity.
 *   3. Derive K = HKDF-SHA256(salt = session_id, info = "privasys-session/v1",
 *      L = 32, IKM = ECDH(sdk_priv, enc_pub)).
 *   4. For every subsequent fetch, encrypt the request body with AES-256-GCM
 *      under K; the enclave decrypts and re-encrypts the response.
 *
 * Only the SDK and the enclave hold K. The gateway (which terminates the
 * outer LE-TLS handshake) never sees plaintext.
 *
 * Wire format (request and response bodies):
 *   Content-Type:  application/privasys-sealed+cbor
 *   Authorization: PrivasysSession <session_id>
 *   Body:          CBOR{v: 1, ctr: u64, ct: bytes}
 *   AD:            method || ":" || path || ":" || session_id   (UTF-8)
 *
 * Nonces are derived deterministically per direction:
 *   nonce[0..4)   = direction prefix (4B)
 *   nonce[4..12)  = ctr_be (big-endian u64)
 *
 * The direction prefix is HKDF("dir-prefix", info = "c2s" or "s2c"), so the
 * same K can safely be used in both directions.
 */

const SEALED_CONTENT_TYPE = 'application/privasys-sealed+cbor';
// Envelope-in-header transport for bodyless methods (GET/HEAD): fetch
// refuses a body on those, so the sealed envelope rides base64url in
// this header. Mirrored by the enclave relay (sessionrelay.go).
const SEALED_ENVELOPE_HEADER = 'X-Privasys-Sealed';
const SEALED_STREAM_CONTENT_TYPE = 'application/privasys-sealed-stream+cbor';
const SESSION_AUTH_SCHEME = 'PrivasysSession';
const HKDF_INFO = new TextEncoder().encode('privasys-session/v1');
const DIR_C2S = new TextEncoder().encode('privasys-dir/c2s');
const DIR_S2C = new TextEncoder().encode('privasys-dir/s2c');
// WebSocket transport uses SEPARATE direction prefixes from the HTTP
// request/response transport. The AES-GCM nonce is `prefix[0..4) || ctr`,
// and reusing a (key, nonce) pair is catastrophic — it leaks the keystream.
// The HTTP and WS channels share the session key K but keep INDEPENDENT
// per-direction counters, so they MUST NOT share a prefix or their nonces
// would collide the moment both are active on one session. Distinct HKDF
// info labels give each channel its own keystream. Mirrored by the enclave
// relay (sessionrelay.go). A session runs at most ONE sealed WebSocket at a
// time (the WS counters restart at 0 per connection); a second concurrent WS
// would reuse this prefix from ctr 0 and is rejected by the relay.
const DIR_WS_C2S = new TextEncoder().encode('privasys-dir/ws-c2s');
const DIR_WS_S2C = new TextEncoder().encode('privasys-dir/ws-s2c');
/** Reserved WS subprotocol marking a sealed session-relay WebSocket. The
 *  session id rides as the SECOND advertised subprotocol because a browser
 *  `WebSocket` cannot set an Authorization header; the relay reads it from
 *  `Sec-WebSocket-Protocol` and echoes back only this marker. Mirrored by
 *  the enclave relay. */
const SEALED_WS_SUBPROTOCOL = 'privasys.sealed.v1';
const INIT_PATH = '/__privasys/session-bootstrap';

/** Provider-shaped object the wallet returns after attestation. */
export interface WalletAttestationResult {
    /** Opaque session id (>=16 bytes) from the enclave's init endpoint. */
    sessionId: string; // base64url
    /** Enclave's ephemeral P-256 public key (SEC1 uncompressed, base64url). */
    encPub: string;
    /** Wallet-signed envelope binding sdk_pub, enc_pub, quote_hash, session_id. */
    walletSignature: string; // base64url, optional verification done by caller
    /** Optional opaque blob the wallet wants the SDK to forward unchanged. */
    appEnvelope?: string;
    /** Optional expiry in epoch milliseconds. */
    expiresAt?: number;
}

export interface SessionInitOptions {
    /**
     * Wallet attestation function. Receives `sdk_pub` (base64url, 65 bytes)
     * and the enclave hostname; must perform end-to-end RA-TLS attestation
     * and return the keys/IDs the enclave issued.
     */
    attestWithWallet: (params: {
        sdkPub: string;
        host: string;
    }) => Promise<WalletAttestationResult>;
    /** Hostname (without scheme) of the enclave app, e.g. "myapp.apps.privasys.org". */
    host: string;
    /** Override the global fetch (useful for tests / SSR). */
    fetchImpl?: typeof fetch;
    /**
     * Optional EncAuth fetcher. When set, the session can silently
     * rebind to the enclave on AEAD-401 errors without bouncing back
     * through the wallet (Phase D / silent-rebind).
     *
     * The callback should fetch a fresh wallet-signed voucher from the
     * IdP at `GET /sessions/{sid}/encauth` and return the parsed JSON
     * envelope. Return null/undefined to skip rebind for this attempt;
     * the caller will then receive the original 401 response.
     */
    getEncAuth?: () => Promise<EncAuthEnvelope | null | undefined>;
}

/**
 * EncAuthEnvelope is the wallet-signed silent-rebind voucher returned
 * by `GET /sessions/{sid}/encauth`. The SDK forwards it verbatim to
 * the enclave's `/__privasys/session-bootstrap` endpoint; verification
 * happens entirely inside the enclave.
 */
/**
 * Stable reason the enclave gives for refusing an EncAuth voucher
 * (crypto-contract §8.4). `workload-changed` = the app's code or
 * configuration changed since the user verified it; `enc-changed` = the
 * hosting platform's identity/measurement changed; both require a fresh
 * wallet ceremony in which the wallet shows the user exactly what
 * changed. `voucher-expired` / `voucher-invalid` are voucher-lifecycle
 * refusals — nothing changed on the enclave side.
 */
export type EncAuthRejectReason =
    | 'enc-changed'
    | 'workload-changed'
    | 'voucher-expired'
    | 'voucher-invalid';

const ENCAUTH_REJECT_REASONS: readonly EncAuthRejectReason[] = [
    'enc-changed',
    'workload-changed',
    'voucher-expired',
    'voucher-invalid',
];

/** Narrow an enclave-supplied reject-reason string to the known union. */
function parseRejectReason(v: string | undefined): EncAuthRejectReason | undefined {
    return ENCAUTH_REJECT_REASONS.includes(v as EncAuthRejectReason)
        ? (v as EncAuthRejectReason)
        : undefined;
}

export interface EncAuthEnvelope {
    v: 1;
    payload: string;  // base64url(canonical CBOR)
    hw_sig: string;   // base64url(64 B R||S)
    idp_sig: string;  // base64url(64 B R||S)
}

interface DerivedKeys {
    aead: CryptoKey;
    c2sPrefix: Uint8Array;
    s2cPrefix: Uint8Array;
    /** Nonce prefixes for the sealed-WebSocket channel (see DIR_WS_*). */
    wsC2sPrefix: Uint8Array;
    wsS2cPrefix: Uint8Array;
}

export class PrivasysSession {
    readonly host: string;
    sessionId: string;
    private keys: DerivedKeys;
    private readonly fetchImpl: typeof fetch;
    private c2sCtr = 0n;
    private s2cCtr = 0n;
    private getEncAuth?: () => Promise<EncAuthEnvelope | null | undefined>;

    private constructor(host: string, sessionId: string, keys: DerivedKeys, fetchImpl: typeof fetch) {
        this.host = host;
        this.sessionId = sessionId;
        this.keys = keys;
        this.fetchImpl = fetchImpl;
    }

    /** Establishes a fresh session. */
    static async create(opts: SessionInitOptions): Promise<PrivasysSession> {
        const fetchImpl = opts.fetchImpl ?? fetch.bind(globalThis);

        const sdkKeyPair = (await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        )) as CryptoKeyPair;
        const sdkPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', sdkKeyPair.publicKey));
        if (sdkPubRaw.byteLength !== 65 || sdkPubRaw[0] !== 0x04) {
            throw new Error('PrivasysSession: unexpected SEC1 encoding');
        }
        const sdkPubB64 = base64UrlEncode(sdkPubRaw);

        const att = await opts.attestWithWallet({ sdkPub: sdkPubB64, host: opts.host });

        const session = await PrivasysSession.fromHandshake({
            host: opts.host,
            sessionId: att.sessionId,
            sdkPrivateKey: sdkKeyPair.privateKey,
            encPub: att.encPub,
            fetchImpl,
        });
        if (opts.getEncAuth) session.getEncAuth = opts.getEncAuth;
        return session;
    }

    /**
     * Resume (re-create) a sealed session purely from an EncAuth voucher —
     * no wallet ceremony, no push. This is the page-reload / cold-start
     * path: `K` is never persisted, so a new ephemeral keypair is
     * generated and the enclave re-derives a fresh session against its
     * long-lived identity key after verifying the voucher.
     *
     * Returns a discriminated result so callers can distinguish "user
     * never had a voucher" from "the enclave refused it" (measurement or
     * identity changed → a wallet ceremony is required).
     */
    static async resume(opts: {
        host: string;
        getEncAuth: () => Promise<EncAuthEnvelope | null | undefined>;
        fetchImpl?: typeof fetch;
    }): Promise<
        | { session: PrivasysSession }
        | { error: 'no-voucher' | 'rejected' | 'unavailable'; reason?: EncAuthRejectReason }
    > {
        const fetchImpl = opts.fetchImpl ?? fetch.bind(globalThis);
        let env: EncAuthEnvelope | null | undefined;
        try {
            env = await opts.getEncAuth();
        } catch {
            return { error: 'unavailable' };
        }
        if (!env) return { error: 'no-voucher' };

        const handshake = await bootstrapWithEncAuth(opts.host, env, fetchImpl);
        if (!handshake.ok) return { error: handshake.error, reason: handshake.reason };

        const session = await PrivasysSession.fromHandshake({
            host: opts.host,
            sessionId: handshake.sessionId,
            sdkPrivateKey: handshake.sdkPrivateKey,
            encPub: handshake.encPub,
            fetchImpl,
            getEncAuth: opts.getEncAuth,
        });
        return { session };
    }

    /**
     * Construct a session from a completed handshake. Use this when the SDK
     * has performed the ECDH out-of-band (e.g. the iframe generated the SDK
     * keypair, the wallet attested the enclave, and `encPub` + `sessionId`
     * came back over the broker).
     */
    static async fromHandshake(opts: {
        host: string;
        sessionId: string;
        sdkPrivateKey: CryptoKey;
        encPub: string;
        fetchImpl?: typeof fetch;
        /** Optional EncAuth fetcher enabling silent rebind (see {@link SessionInitOptions.getEncAuth}). */
        getEncAuth?: () => Promise<EncAuthEnvelope | null | undefined>;
    }): Promise<PrivasysSession> {
        const fetchImpl = opts.fetchImpl ?? fetch.bind(globalThis);

        const encPubRaw = base64UrlDecode(opts.encPub);
        if (encPubRaw.byteLength !== 65 || encPubRaw[0] !== 0x04) {
            throw new Error('PrivasysSession: enclave public key not SEC1 uncompressed');
        }
        const encPubKey = await crypto.subtle.importKey(
            'raw',
            encPubRaw as BufferSource,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            [],
        );

        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: encPubKey },
            opts.sdkPrivateKey,
            256,
        );

        const sessionIdBytes = base64UrlDecode(opts.sessionId);
        const ikm = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits', 'deriveKey']);
        const aeadBits = await crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: sessionIdBytes as BufferSource, info: HKDF_INFO as BufferSource },
            ikm,
            256,
        );
        const aead = await crypto.subtle.importKey(
            'raw',
            aeadBits,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
        const c2sPrefix = new Uint8Array(
            await crypto.subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: sessionIdBytes as BufferSource, info: DIR_C2S as BufferSource },
                ikm,
                32,
            ),
        );
        const s2cPrefix = new Uint8Array(
            await crypto.subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: sessionIdBytes as BufferSource, info: DIR_S2C as BufferSource },
                ikm,
                32,
            ),
        );
        const wsC2sPrefix = new Uint8Array(
            await crypto.subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: sessionIdBytes as BufferSource, info: DIR_WS_C2S as BufferSource },
                ikm,
                32,
            ),
        );
        const wsS2cPrefix = new Uint8Array(
            await crypto.subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: sessionIdBytes as BufferSource, info: DIR_WS_S2C as BufferSource },
                ikm,
                32,
            ),
        );

        const session = new PrivasysSession(opts.host, opts.sessionId, { aead, c2sPrefix, s2cPrefix, wsC2sPrefix, wsS2cPrefix }, fetchImpl);
        if (opts.getEncAuth) session.getEncAuth = opts.getEncAuth;
        return session;
    }

    /**
     * Sends a sealed request to the enclave. `path` must include a leading
     * slash and any query string. `body` is encoded as JSON if it is not
     * already a Uint8Array / string.
     */
    async request(method: string, path: string, body?: unknown, init?: RequestInit): Promise<SealedResponse> {
        const r = await this.requestOnce(method, path, body, init);
        // Silent-rebind: when the enclave rejected our session (expired
        // or evicted) and the caller wired a getEncAuth fetcher, ask
        // the IdP for a fresh voucher and re-bootstrap without going
        // through the wallet. The enclave's plaintext error responses
        // come back unsealed with status 401, which is also what the
        // outer gateway returns when there's no session at all.
        if (
            r.status === 401 &&
            !r.sealed &&
            this.getEncAuth &&
            // Avoid infinite loops: skip rebind on the rebind path itself.
            path !== INIT_PATH
        ) {
            const rebound = await this.tryRebind();
            if (rebound) {
                return this.requestOnce(method, path, body, init);
            }
        }
        return r;
    }

    private async requestOnce(method: string, path: string, body?: unknown, init?: RequestInit): Promise<SealedResponse> {
        const upperMethod = method.toUpperCase();
        const ad = encodeAD(upperMethod, path, this.sessionId);

        const plaintext = serializePlaintext(body);
        const ctr = this.c2sCtr++;
        const nonce = makeNonce(this.keys.c2sPrefix, ctr);
        const ct = new Uint8Array(
            await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: ad as BufferSource },
                this.keys.aead,
                plaintext as BufferSource,
            ),
        );
        const reqBody = encodeSealed({ v: 1, ctr, ct });

        const headers = new Headers(init?.headers);
        headers.set('Content-Type', SEALED_CONTENT_TYPE);
        headers.set('Authorization', `${SESSION_AUTH_SCHEME} ${this.sessionId}`);

        // fetch forbids a body on GET/HEAD, so for those methods the (tiny —
        // empty-plaintext) envelope travels in the X-Privasys-Sealed header
        // instead. The AAD already binds the real method and path, so the
        // header envelope cannot be replayed onto another route or verb.
        const bodyless = upperMethod === 'GET' || upperMethod === 'HEAD';
        if (bodyless) headers.set(SEALED_ENVELOPE_HEADER, base64UrlEncode(reqBody));

        const url = `https://${this.host}${path}`;
        const resp = await this.fetchImpl(url, {
            ...init,
            method: upperMethod,
            headers,
            ...(bodyless ? {} : { body: reqBody as BodyInit }),
        });

        const respBody = new Uint8Array(await resp.arrayBuffer());
        // Allow plaintext error responses (e.g. 502 from the gateway with no
        // session-relay context). The caller can branch on status + sealed.
        const respCT = resp.headers.get('content-type') ?? '';
        if (respCT.startsWith(SEALED_STREAM_CONTENT_TYPE)) {
            // Drain the stream into a single Uint8Array so request() retains
            // its single-shot semantics. For SSE callers, use stream() below.
            const chunks: Uint8Array[] = [];
            for await (const chunk of decodeFrameStream(respBody, this.keys.aead, this.keys.s2cPrefix, ad)) {
                chunks.push(chunk);
            }
            const inner = parseInnerStatus(resp.headers, resp.status);
            return { status: inner, sealed: true, body: concat(chunks), headers: resp.headers };
        }
        if (!respCT.startsWith(SEALED_CONTENT_TYPE)) {
            return { status: resp.status, sealed: false, body: respBody, headers: resp.headers };
        }

        const sealed = decodeSealed(respBody);
        const respNonce = makeNonce(this.keys.s2cPrefix, sealed.ctr);
        const pt = new Uint8Array(
            await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: respNonce as BufferSource, additionalData: ad as BufferSource },
                this.keys.aead,
                sealed.ct as BufferSource,
            ),
        );
        // Track expected ctr for replay rejection on subsequent responses.
        if (sealed.ctr >= this.s2cCtr) {
            this.s2cCtr = sealed.ctr + 1n;
        }
        return { status: resp.status, sealed: true, body: pt, headers: resp.headers };
    }

    /**
     * Silent rebind: replace this session's keys + sessionId in place
     * by re-bootstrapping against the enclave with a wallet-issued
     * EncAuth voucher. Returns true on success.
     *
     * Failures are swallowed (returns false) so the original 401
     * propagates unchanged to the caller, who can then trigger a
     * fresh wallet ceremony.
     */
    private async tryRebind(): Promise<boolean> {
        if (!this.getEncAuth) return false;
        let env: EncAuthEnvelope | null | undefined;
        try {
            env = await this.getEncAuth();
        } catch {
            return false;
        }
        if (!env) return false;

        const handshake = await bootstrapWithEncAuth(this.host, env, this.fetchImpl);
        if (!handshake.ok) return false;

        try {
            const reborn = await PrivasysSession.fromHandshake({
                host: this.host,
                sessionId: handshake.sessionId,
                sdkPrivateKey: handshake.sdkPrivateKey,
                encPub: handshake.encPub,
                fetchImpl: this.fetchImpl,
            });
            // Adopt the new keys + sessionId in place. Counters are
            // reset because the AAD now embeds the new sessionId.
            this.sessionId = reborn.sessionId;
            this.keys = reborn.keys;
            this.c2sCtr = 0n;
            this.s2cCtr = 0n;
            return true;
        } catch {
            return false;
        }
    }

    /** Convenience for JSON responses. */
    async json<T = unknown>(method: string, path: string, body?: unknown, init?: RequestInit): Promise<T> {
        const r = await this.request(method, path, body, init);
        if (r.status >= 400) {
            throw new Error(`PrivasysSession ${method} ${path}: ${r.status}`);
        }
        return JSON.parse(new TextDecoder().decode(r.body)) as T;
    }

    /**
     * Open a sealed, bidirectional WebSocket to the enclave app at `path`.
     *
     * Every application message — in either direction — is a BINARY frame
     * carrying one AES-GCM sealed envelope under this session's key, so the
     * TLS-terminating gateway (which relays the WebSocket to the enclave)
     * never sees plaintext. The enclave relay unseals client frames before
     * handing them to the app's own WebSocket and seals the app's frames on
     * the way back.
     *
     * Because a browser `WebSocket` cannot set an Authorization header, the
     * session id is carried as the second advertised subprotocol
     * (`[SEALED_WS_SUBPROTOCOL, sessionId]`); the relay validates it during
     * the upgrade. Only ONE sealed WebSocket may be open per session at a
     * time (see DIR_WS_*): a second concurrent one reuses the WS keystream
     * and the relay rejects it.
     *
     * Unlike `request`/`stream`, a WebSocket cannot be silently rebound: if
     * the session is evicted the enclave closes the socket, surfaced via
     * `onClose`. Callers recover by re-establishing the session (a fresh
     * voucher resume / ceremony) and opening a new WebSocket.
     *
     * @param path Absolute path (must start with '/'), e.g. `/v1/live`.
     */
    openWebSocket(path: string, opts?: OpenWebSocketOptions): SealedWebSocket {
        if (!path.startsWith('/')) {
            throw new Error('openWebSocket: path must start with "/"');
        }
        const WS = opts?.WebSocketImpl ?? (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
        if (!WS) {
            throw new Error('openWebSocket: no WebSocket implementation available (pass opts.WebSocketImpl)');
        }
        // AAD is fixed for the whole connection ("WS:<path>:<sessionId>"),
        // matching the HTTP transport's method:path:session binding; per-frame
        // uniqueness comes from the counter in the nonce.
        const ad = encodeAD('WS', path, this.sessionId);
        const url = `wss://${this.host}${path}`;
        const ws = new WS(url, [SEALED_WS_SUBPROTOCOL, this.sessionId, ...(opts?.protocols ?? [])]);
        ws.binaryType = 'arraybuffer';
        return new SealedWebSocketImpl(
            ws,
            this.keys.aead,
            this.keys.wsC2sPrefix,
            this.keys.wsS2cPrefix,
            ad,
        );
    }

    /**
     * Sends a sealed request and returns a stream of decrypted plaintext
     * chunks. Use for SSE / chunked endpoints; for one-shot calls use
     * {@link request}. The returned object carries the inner HTTP status
     * (decoded from `X-Privasys-Inner-Status`) and a ReadableStream of the
     * decrypted body bytes.
     */
    async stream(method: string, path: string, body?: unknown, init?: RequestInit): Promise<SealedStreamResponse> {
        const r = await this.streamOnce(method, path, body, init);
        // Silent-rebind for the streaming path, mirroring request(): when
        // the enclave no longer recognises our session it answers with an
        // UNSEALED 401 (same shape the gateway returns when there's no
        // session at all). If the caller wired a getEncAuth fetcher, fetch
        // a fresh voucher, re-bootstrap, and replay the stream once — so a
        // back-end redeploy that kept its measurement recovers transparently
        // instead of surfacing a dead "chat request failed: 401" to the UI.
        // A measurement change makes tryRebind() return false and the
        // original 401 propagates, which the front-end turns into a
        // reconnect prompt.
        if (
            r.status === 401 &&
            !r.sealed &&
            this.getEncAuth &&
            path !== INIT_PATH
        ) {
            const rebound = await this.tryRebind();
            if (rebound) {
                // Discard the unsealed error stream before replaying.
                try { await r.body.cancel(); } catch { /* tearing down */ }
                return this.streamOnce(method, path, body, init);
            }
        }
        return r;
    }

    private async streamOnce(method: string, path: string, body?: unknown, init?: RequestInit): Promise<SealedStreamResponse> {
        const upperMethod = method.toUpperCase();
        const ad = encodeAD(upperMethod, path, this.sessionId);

        const plaintext = serializePlaintext(body);
        const ctr = this.c2sCtr++;
        const nonce = makeNonce(this.keys.c2sPrefix, ctr);
        const ct = new Uint8Array(
            await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: ad as BufferSource },
                this.keys.aead,
                plaintext as BufferSource,
            ),
        );
        const reqBody = encodeSealed({ v: 1, ctr, ct });

        const headers = new Headers(init?.headers);
        headers.set('Content-Type', SEALED_CONTENT_TYPE);
        headers.set('Authorization', `${SESSION_AUTH_SCHEME} ${this.sessionId}`);

        // fetch forbids a body on GET/HEAD, so for those methods the (tiny —
        // empty-plaintext) envelope travels in the X-Privasys-Sealed header
        // instead. The AAD already binds the real method and path, so the
        // header envelope cannot be replayed onto another route or verb.
        const bodyless = upperMethod === 'GET' || upperMethod === 'HEAD';
        if (bodyless) headers.set(SEALED_ENVELOPE_HEADER, base64UrlEncode(reqBody));

        const url = `https://${this.host}${path}`;
        const resp = await this.fetchImpl(url, {
            ...init,
            method: upperMethod,
            headers,
            ...(bodyless ? {} : { body: reqBody as BodyInit }),
        });

        const respCT = resp.headers.get('content-type') ?? '';
        if (!respCT.startsWith(SEALED_STREAM_CONTENT_TYPE)) {
            // Fall back: drain as single envelope (or raw passthrough) and
            // expose it as a one-chunk stream.
            const buf = new Uint8Array(await resp.arrayBuffer());
            let chunks: Uint8Array[] = [buf];
            let sealed = false;
            let status = resp.status;
            if (respCT.startsWith(SEALED_CONTENT_TYPE)) {
                const env = decodeSealed(buf);
                const respNonce = makeNonce(this.keys.s2cPrefix, env.ctr);
                const pt = new Uint8Array(
                    await crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: respNonce as BufferSource, additionalData: ad as BufferSource },
                        this.keys.aead,
                        env.ct as BufferSource,
                    ),
                );
                chunks = [pt];
                sealed = true;
                status = parseInnerStatus(resp.headers, resp.status);
            }
            const single = new ReadableStream<Uint8Array>({
                start(controller) {
                    for (const c of chunks) controller.enqueue(c);
                    controller.close();
                },
            });
            return { status, sealed, headers: resp.headers, body: single };
        }

        const aead = this.keys.aead;
        const s2cPrefix = this.keys.s2cPrefix;
        const reader = resp.body!.getReader();
        const status = parseInnerStatus(resp.headers, resp.status);
        // Per-frame flush: each `pull()` advances the decoder by exactly
        // one sealed frame (or closes the stream). The previous
        // implementation drained the entire async iterator inside a
        // single pull, so the consumer only saw frames after the inner
        // loop finished or backpressure kicked in. For SSE / token
        // streaming this materialised as bursty UI updates: many
        // tokens piling up between paints. Yielding one frame per pull
        // hands every decoded chunk straight to the caller as soon as
        // the network produces it, which is what the chat-relay
        // postMessage bridge needs to forward `stream-chunk` per token.
        const iter = decodeFrameReader(reader, aead, s2cPrefix, ad);
        const stream = new ReadableStream<Uint8Array>({
            async pull(controller) {
                try {
                    const { value, done } = await iter.next();
                    if (done) {
                        controller.close();
                        return;
                    }
                    controller.enqueue(value);
                } catch (e) {
                    controller.error(e);
                }
            },
            cancel(reason) {
                // Best-effort cleanup of the underlying reader and the
                // generator's internal state. Errors here are not
                // observable by the caller (the stream is being torn
                // down) so we swallow them.
                iter.return?.(undefined).catch(() => undefined);
                reader.cancel(reason).catch(() => undefined);
            },
        });
        return { status, sealed: true, headers: resp.headers, body: stream };
    }
}

export interface SealedStreamResponse {
    status: number;
    sealed: boolean;
    headers: Headers;
    body: ReadableStream<Uint8Array>;
}

export interface SealedResponse {
    status: number;
    /** True if the response body has been decrypted; false for raw passthrough (gateway 5xx). */
    sealed: boolean;
    body: Uint8Array;
    headers: Headers;
}

export interface OpenWebSocketOptions {
    /** WebSocket implementation to use (default: `globalThis.WebSocket`).
     *  Inject for Node or tests — e.g. the `ws` package's `WebSocket`. */
    WebSocketImpl?: typeof WebSocket;
    /** Extra subprotocols advertised AFTER the reserved marker + session id.
     *  Rarely needed; the app rarely negotiates a subprotocol through the
     *  sealed relay. */
    protocols?: string[];
}

/**
 * A sealed, message-oriented WebSocket. `send` accepts bytes / string / JSON
 * and seals each into one binary frame; `onMessage` delivers decrypted
 * plaintext bytes. Frames are counter-ordered per direction; a replayed or
 * out-of-order inbound frame is rejected (it closes the socket with an error).
 */
export interface SealedWebSocket {
    /** Resolves when the socket is open (the relay accepted the sealed
     *  subprotocol); rejects if it closes or errors before opening. */
    readonly ready: Promise<void>;
    /** True once open and not yet closing/closed. */
    readonly open: boolean;
    /** Seal and send one application message. Calls made before the socket
     *  opens are queued and flushed, in order, once it opens. */
    send(data: Uint8Array | ArrayBuffer | string | object): void;
    /** Register a decrypted-message handler. Returns an unsubscribe fn. */
    onMessage(cb: (data: Uint8Array) => void): () => void;
    /** Register a close handler. */
    onClose(cb: (info: { code: number; reason: string; wasClean: boolean }) => void): void;
    /** Register an error handler: a transport error, or an inbound frame that
     *  failed to decrypt or violated ordering (the latter also closes). */
    onError(cb: (err: Error) => void): void;
    /** Initiate a clean close. */
    close(code?: number, reason?: string): void;
}

/**
 * Sealed-WebSocket implementation. Sealing (outbound) and unsealing (inbound)
 * are async (WebCrypto), but each direction's counter MUST advance in
 * send / receive order, so both are serialised through a per-direction promise
 * chain. Outbound frames additionally wait for the socket to open before they
 * are put on the wire, preserving order across the open boundary.
 */
class SealedWebSocketImpl implements SealedWebSocket {
    readonly ready: Promise<void>;
    private resolveReady!: () => void;
    private rejectReady!: (e: Error) => void;
    private readyPending = true;

    private c2sCtr = 0n;
    private s2cCtr = 0n;
    private opened = false;
    private closedLocally = false;
    private outChain: Promise<void> = Promise.resolve();
    private inChain: Promise<void> = Promise.resolve();

    private readonly msgCbs = new Set<(d: Uint8Array) => void>();
    private readonly closeCbs = new Set<(i: { code: number; reason: string; wasClean: boolean }) => void>();
    private readonly errCbs = new Set<(e: Error) => void>();

    constructor(
        private readonly ws: WebSocket,
        private readonly aead: CryptoKey,
        private readonly c2sPrefix: Uint8Array,
        private readonly s2cPrefix: Uint8Array,
        private readonly ad: Uint8Array,
    ) {
        this.ready = new Promise<void>((resolve, reject) => {
            this.resolveReady = resolve;
            this.rejectReady = reject;
        });
        // A rejected `ready` that no caller awaits must not surface as an
        // unhandled rejection; the close/error callbacks carry the signal too.
        this.ready.catch(() => undefined);

        ws.onopen = () => {
            this.opened = true;
            if (this.readyPending) {
                this.readyPending = false;
                this.resolveReady();
            }
        };
        ws.onmessage = (ev: MessageEvent) => this.onWireMessage(ev);
        ws.onerror = () => this.emitError(new Error('sealed websocket transport error'));
        ws.onclose = (ev: CloseEvent) => {
            if (this.readyPending) {
                this.readyPending = false;
                this.rejectReady(new Error(`sealed websocket closed before open (code ${ev.code})`));
            }
            for (const cb of this.closeCbs) {
                try { cb({ code: ev.code, reason: ev.reason, wasClean: ev.wasClean }); } catch { /* isolate */ }
            }
        };
    }

    get open(): boolean {
        return this.opened && !this.closedLocally && this.ws.readyState === 1 /* OPEN */;
    }

    send(data: Uint8Array | ArrayBuffer | string | object): void {
        if (this.closedLocally) throw new Error('sealed websocket is closed');
        const plaintext = serializePlaintext(data);
        // Assign the counter at ENQUEUE time so on-wire order matches call
        // order even though sealing resolves asynchronously.
        const ctr = this.c2sCtr++;
        this.outChain = this.outChain.then(async () => {
            if (this.closedLocally) return;
            let frame: Uint8Array;
            try {
                const nonce = makeNonce(this.c2sPrefix, ctr);
                const ct = new Uint8Array(
                    await crypto.subtle.encrypt(
                        { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: this.ad as BufferSource },
                        this.aead,
                        plaintext as BufferSource,
                    ),
                );
                frame = encodeSealed({ v: 1, ctr, ct });
            } catch (e) {
                this.emitError(e instanceof Error ? e : new Error('sealed websocket: encrypt failed'));
                return;
            }
            // Wait for open so pre-open sends flush in order; bail if the
            // socket died in the meantime.
            if (!this.opened) {
                try { await this.ready; } catch { return; }
            }
            if (this.ws.readyState !== 1) return;
            this.ws.send(frame.buffer as ArrayBuffer);
        });
        // Chain errors are reported via emitError; keep the chain alive.
        this.outChain = this.outChain.catch(() => undefined);
    }

    private onWireMessage(ev: MessageEvent): void {
        const raw = ev.data;
        if (typeof raw === 'string') {
            this.emitError(new Error('sealed websocket: text frame rejected (binary sealed frames only)'));
            this.close(1003, 'binary frames only');
            return;
        }
        this.inChain = this.inChain.then(async () => {
            if (this.closedLocally) return;
            let plaintext: Uint8Array;
            try {
                const bytes = raw instanceof ArrayBuffer ? new Uint8Array(raw) : new Uint8Array(await (raw as Blob).arrayBuffer());
                const env = decodeSealed(bytes);
                // Strict monotonic replay/reorder rejection, matching the HTTP
                // transport: accept only a counter at or beyond the next
                // expected value and advance past it.
                if (env.ctr < this.s2cCtr) {
                    throw new Error(`sealed websocket: replayed/out-of-order frame (ctr ${env.ctr} < ${this.s2cCtr})`);
                }
                const nonce = makeNonce(this.s2cPrefix, env.ctr);
                plaintext = new Uint8Array(
                    await crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: this.ad as BufferSource },
                        this.aead,
                        env.ct as BufferSource,
                    ),
                );
                this.s2cCtr = env.ctr + 1n;
            } catch (e) {
                this.emitError(e instanceof Error ? e : new Error('sealed websocket: decrypt failed'));
                this.close(1002, 'protocol error');
                return;
            }
            for (const cb of this.msgCbs) {
                try { cb(plaintext); } catch { /* isolate listener errors */ }
            }
        }).catch(() => undefined);
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
        try { this.ws.close(code, reason); } catch { /* already closing */ }
    }

    private emitError(err: Error): void {
        for (const cb of this.errCbs) {
            try { cb(err); } catch { /* isolate */ }
        }
    }
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

/**
 * Run an EncAuth-vouched bootstrap against the enclave: generate a fresh
 * ephemeral SDK keypair, POST it with the voucher, and return the
 * handshake inputs. Shared by silent rebind (`tryRebind`) and cold
 * resume (`PrivasysSession.resume`).
 *
 * `rejected` means the enclave actively refused the voucher — the
 * measurement, app workload or enclave identity changed and a wallet
 * ceremony is required. When the enclave says WHY (`encauth_reject` in
 * the bootstrap body, mirrored in `X-Privasys-Reason` for non-browser
 * clients — the gateway's CORS does not expose custom headers to
 * browser JS), `reason` carries the stable token so the UI can explain
 * the wake: `workload-changed` (the app was updated), `enc-changed`
 * (the hosting platform changed), `voucher-expired`, `voucher-invalid`.
 * `unavailable` is a transport/parse failure worth retrying.
 */
async function bootstrapWithEncAuth(
    host: string,
    env: EncAuthEnvelope,
    fetchImpl: typeof fetch,
): Promise<
    | { ok: true; sessionId: string; encPub: string; sdkPrivateKey: CryptoKey }
    | { ok: false; error: 'rejected' | 'unavailable'; reason?: EncAuthRejectReason }
> {
    try {
        const sdkKeyPair = (await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        )) as CryptoKeyPair;
        const sdkPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', sdkKeyPair.publicKey));
        const sdkPubB64 = base64UrlEncode(sdkPubRaw);

        const url = `https://${host}${INIT_PATH}`;
        const resp = await fetchImpl(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sdk_pub: sdkPubB64, encauth: env }),
        });
        if (!resp.ok) return { ok: false, error: 'rejected' };

        const data = (await resp.json()) as {
            session_id: string;
            enc_pub: string;
            sub?: string;
            encauth_reject?: string;
        };
        // If the enclave couldn't accept the voucher it reports the stable
        // reason in the body (readable regardless of CORS) and falls
        // through to the legacy random-id path. Header fallback covers
        // non-browser fetch implementations against older enclaves.
        const reason = parseRejectReason(
            data.encauth_reject ?? resp.headers.get('X-Privasys-Reason') ?? undefined,
        );
        if (reason || resp.headers.get('X-Privasys-EncAuth-Reject')) {
            return { ok: false, error: 'rejected', reason };
        }
        // A voucher-backed bootstrap that the enclave accepted always
        // carries the authenticated subject. Its absence means the voucher
        // was NOT consumed (e.g. an enclave that predates the reject-reason
        // body field refused it, and the gateway's CORS hid the header):
        // adopting the session would leave the app unauthenticated, so
        // treat it as a refusal and fall back to a wallet ceremony.
        if (!data.sub) return { ok: false, error: 'rejected' };
        if (!data.session_id || !data.enc_pub) return { ok: false, error: 'rejected' };

        // SECURITY: pin the response enc_pub to the wallet-attested
        // enc_pub carried (and signed) inside the voucher. The bootstrap
        // endpoint is exempt from sealed transport, so this response
        // crosses the gateway-terminated leg in the clear. Without this
        // check a malicious intermediary could substitute its own
        // enc_pub, the SDK would derive K against it, and the "sealed"
        // session would be readable by that intermediary — defeating the
        // whole point of session relay. In the honest path the enclave
        // only accepts the voucher when its own identity equals the
        // bound enc_pub, so the genuine response always matches.
        let boundEncPub: Uint8Array;
        try {
            boundEncPub = extractVoucherEncPub(env.payload);
        } catch {
            return { ok: false, error: 'rejected' };
        }
        let respEncPub: Uint8Array;
        try {
            respEncPub = base64UrlDecode(data.enc_pub);
        } catch {
            return { ok: false, error: 'rejected' };
        }
        if (!bytesEqual(respEncPub, boundEncPub)) {
            return { ok: false, error: 'rejected' };
        }

        return { ok: true, sessionId: data.session_id, encPub: data.enc_pub, sdkPrivateKey: sdkKeyPair.privateKey };
    } catch {
        return { ok: false, error: 'unavailable' };
    }
}

/**
 * Extract the wallet-attested `enc_pub` (SEC1 uncompressed, 65 bytes)
 * from an EncAuth voucher payload (base64url canonical CBOR, integer
 * keys 1..10 ascending — crypto-contract §8.1; enc_pub is key 6). Strict
 * walk: rejects anything that is not the expected map shape. Used to
 * pin the enclave identity the silent-rebind / resume session is keyed
 * against. Throws on any malformation.
 */
function extractVoucherEncPub(payloadB64: string): Uint8Array {
    const buf = base64UrlDecode(payloadB64);
    let off = 0;
    if (buf[off] !== 0xaa) throw new Error('encauth payload: expected map(10)');
    off += 1;
    let encPub: Uint8Array | null = null;
    for (let i = 0; i < 10; i++) {
        const [key, kOff] = readUint(buf, off);
        off = kOff;
        const major = buf[off] >> 5;
        if (major === 0) {
            const [, o] = readUint(buf, off);
            off = o;
        } else if (major === 2) {
            const [b, o] = readByteString(buf, off);
            off = o;
            if (key === 6n) encPub = b;
        } else if (major === 3) {
            const [, o] = readTextString(buf, off);
            off = o;
        } else {
            throw new Error('encauth payload: unexpected major type');
        }
    }
    if (!encPub || encPub.byteLength !== 65 || encPub[0] !== 0x04) {
        throw new Error('encauth payload: missing or malformed enc_pub');
    }
    return encPub;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.byteLength !== b.byteLength) return false;
    let diff = 0;
    for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

function serializePlaintext(body: unknown): Uint8Array {
    if (body == null) return new Uint8Array(0);
    if (body instanceof Uint8Array) return body;
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (typeof body === 'string') return new TextEncoder().encode(body);
    return new TextEncoder().encode(JSON.stringify(body));
}

function encodeAD(method: string, path: string, sessionId: string): Uint8Array {
    return new TextEncoder().encode(`${method}:${path}:${sessionId}`);
}

function makeNonce(prefix: Uint8Array, ctr: bigint): Uint8Array {
    const nonce = new Uint8Array(12);
    nonce.set(prefix.subarray(0, 4), 0);
    const view = new DataView(nonce.buffer);
    view.setBigUint64(4, ctr, false); // big-endian
    return nonce;
}

// -----------------------------------------------------------------------------
// minimal CBOR for the 3-key sealed envelope
// -----------------------------------------------------------------------------

interface SealedEnvelope {
    v: number;
    ctr: bigint;
    ct: Uint8Array;
}

function encodeSealed(env: SealedEnvelope): Uint8Array {
    // map(3): 0xa3
    //   "v"  -> uint(env.v)
    //   "ctr"-> uint(env.ctr)        (always major-type 0)
    //   "ct" -> byte string(env.ct)  (major-type 2)
    const parts: Uint8Array[] = [];
    parts.push(new Uint8Array([0xa3]));
    parts.push(cborTextString('v'));
    parts.push(cborUint(BigInt(env.v)));
    parts.push(cborTextString('ctr'));
    parts.push(cborUint(env.ctr));
    parts.push(cborTextString('ct'));
    parts.push(cborByteString(env.ct));
    return concat(parts);
}

function decodeSealed(buf: Uint8Array): SealedEnvelope {
    let off = 0;
    if (buf[off] !== 0xa3) throw new Error('CBOR: expected map(3)');
    off += 1;
    const out: Partial<SealedEnvelope> = {};
    for (let i = 0; i < 3; i++) {
        const [key, kOff] = readTextString(buf, off);
        off = kOff;
        if (key === 'v') {
            const [n, vOff] = readUint(buf, off);
            out.v = Number(n);
            off = vOff;
        } else if (key === 'ctr') {
            const [n, vOff] = readUint(buf, off);
            out.ctr = n;
            off = vOff;
        } else if (key === 'ct') {
            const [b, vOff] = readByteString(buf, off);
            out.ct = b;
            off = vOff;
        } else {
            throw new Error(`CBOR: unexpected key ${key}`);
        }
    }
    if (out.v == null || out.ctr == null || out.ct == null) throw new Error('CBOR: incomplete envelope');
    return out as SealedEnvelope;
}

function cborUint(n: bigint): Uint8Array {
    if (n < 0n) throw new Error('cborUint: negative');
    if (n < 24n) return new Uint8Array([Number(n)]);
    if (n < 256n) return new Uint8Array([0x18, Number(n)]);
    if (n < 65536n) {
        const b = new Uint8Array(3);
        b[0] = 0x19;
        new DataView(b.buffer).setUint16(1, Number(n), false);
        return b;
    }
    if (n < 4294967296n) {
        const b = new Uint8Array(5);
        b[0] = 0x1a;
        new DataView(b.buffer).setUint32(1, Number(n), false);
        return b;
    }
    const b = new Uint8Array(9);
    b[0] = 0x1b;
    new DataView(b.buffer).setBigUint64(1, n, false);
    return b;
}

function cborHeader(majorType: number, n: bigint): Uint8Array {
    const u = cborUint(n);
    u[0] = (majorType << 5) | (u[0] & 0x1f);
    return u;
}

function cborTextString(s: string): Uint8Array {
    const enc = new TextEncoder().encode(s);
    return concat([cborHeader(3, BigInt(enc.byteLength)), enc]);
}

function cborByteString(b: Uint8Array): Uint8Array {
    return concat([cborHeader(2, BigInt(b.byteLength)), b]);
}

function readUint(buf: Uint8Array, off: number): [bigint, number] {
    const major = buf[off] >> 5;
    if (major !== 0) throw new Error(`CBOR: expected uint, got major=${major}`);
    return readArgument(buf, off);
}

function readTextString(buf: Uint8Array, off: number): [string, number] {
    const major = buf[off] >> 5;
    if (major !== 3) throw new Error(`CBOR: expected text, got major=${major}`);
    const [len, o] = readArgument(buf, off);
    const n = Number(len);
    return [new TextDecoder().decode(buf.subarray(o, o + n)), o + n];
}

function readByteString(buf: Uint8Array, off: number): [Uint8Array, number] {
    const major = buf[off] >> 5;
    if (major !== 2) throw new Error(`CBOR: expected bytes, got major=${major}`);
    const [len, o] = readArgument(buf, off);
    const n = Number(len);
    return [buf.subarray(o, o + n), o + n];
}

function readArgument(buf: Uint8Array, off: number): [bigint, number] {
    const ai = buf[off] & 0x1f;
    if (ai < 24) return [BigInt(ai), off + 1];
    if (ai === 24) return [BigInt(buf[off + 1]), off + 2];
    if (ai === 25) {
        return [BigInt(new DataView(buf.buffer, buf.byteOffset + off + 1, 2).getUint16(0, false)), off + 3];
    }
    if (ai === 26) {
        return [BigInt(new DataView(buf.buffer, buf.byteOffset + off + 1, 4).getUint32(0, false)), off + 5];
    }
    if (ai === 27) {
        return [new DataView(buf.buffer, buf.byteOffset + off + 1, 8).getBigUint64(0, false), off + 9];
    }
    throw new Error(`CBOR: indefinite-length not supported (ai=${ai})`);
}

function concat(parts: Uint8Array<ArrayBufferLike>[]): Uint8Array {
    let total = 0;
    for (const p of parts) total += p.byteLength;
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.byteLength;
    }
    return out;
}

function parseInnerStatus(headers: Headers, fallback: number): number {
    const v = headers.get('x-privasys-inner-status');
    if (!v) return fallback;
    const n = parseInt(v, 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
}

/**
 * Decode a complete sealed-stream byte buffer into a series of decrypted
 * plaintext chunks. Used by request() when the response is a stream that
 * has already been fully buffered.
 */
async function* decodeFrameStream(
    buf: Uint8Array,
    aead: CryptoKey,
    s2cPrefix: Uint8Array,
    ad: Uint8Array,
): AsyncGenerator<Uint8Array> {
    let off = 0;
    while (off + 4 <= buf.byteLength) {
        const len = new DataView(buf.buffer, buf.byteOffset + off, 4).getUint32(0, false);
        off += 4;
        if (len === 0) return;
        if (off + len > buf.byteLength) throw new Error('sealed-stream: truncated frame');
        const env = decodeSealed(buf.subarray(off, off + len));
        off += len;
        const nonce = makeNonce(s2cPrefix, env.ctr);
        const pt = new Uint8Array(
            await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: ad as BufferSource },
                aead,
                env.ct as BufferSource,
            ),
        );
        yield pt;
    }
}

/**
 * Decode an in-flight sealed-stream from a ReadableStream<Uint8Array> reader.
 * Yields each decrypted plaintext chunk as soon as a full frame is available.
 */
async function* decodeFrameReader(
    reader: ReadableStreamDefaultReader<Uint8Array>,
    aead: CryptoKey,
    s2cPrefix: Uint8Array,
    ad: Uint8Array,
): AsyncGenerator<Uint8Array> {
    let buf: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    for (;;) {
        // Need 4 bytes for length.
        while (buf.byteLength < 4) {
            const { value, done } = await reader.read();
            if (done) {
                if (buf.byteLength === 0) return;
                throw new Error('sealed-stream: truncated length header');
            }
            buf = concat([buf, value]);
        }
        const len = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false);
        if (len === 0) return;
        // Need len bytes for envelope.
        while (buf.byteLength < 4 + len) {
            const { value, done } = await reader.read();
            if (done) throw new Error('sealed-stream: truncated frame');
            buf = concat([buf, value]);
        }
        const env = decodeSealed(buf.subarray(4, 4 + len));
        buf = buf.slice(4 + len);
        const nonce = makeNonce(s2cPrefix, env.ctr);
        const pt = new Uint8Array(
            await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: ad as BufferSource },
                aead,
                env.ct as BufferSource,
            ),
        );
        yield pt;
    }
}

function base64UrlEncode(b: Uint8Array): string {
    let s = '';
    for (let i = 0; i < b.byteLength; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(s: string): Uint8Array {
    const norm = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = norm.length % 4 === 0 ? '' : '='.repeat(4 - (norm.length % 4));
    const raw = atob(norm + pad);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
}
