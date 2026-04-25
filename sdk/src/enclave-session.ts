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
const SESSION_AUTH_SCHEME = 'PrivasysSession';
const HKDF_INFO = new TextEncoder().encode('privasys-session/v1');
const DIR_C2S = new TextEncoder().encode('privasys-dir/c2s');
const DIR_S2C = new TextEncoder().encode('privasys-dir/s2c');

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
}

interface DerivedKeys {
    aead: CryptoKey;
    c2sPrefix: Uint8Array;
    s2cPrefix: Uint8Array;
}

export class PrivasysSession {
    readonly host: string;
    readonly sessionId: string;
    private readonly keys: DerivedKeys;
    private readonly fetchImpl: typeof fetch;
    private c2sCtr = 0n;
    private s2cCtr = 0n;

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

        const encPubRaw = base64UrlDecode(att.encPub);
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
            sdkKeyPair.privateKey,
            256,
        );

        const sessionIdBytes = base64UrlDecode(att.sessionId);
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
                32, // 4 bytes
            ),
        );
        const s2cPrefix = new Uint8Array(
            await crypto.subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: sessionIdBytes as BufferSource, info: DIR_S2C as BufferSource },
                ikm,
                32,
            ),
        );

        return new PrivasysSession(opts.host, att.sessionId, { aead, c2sPrefix, s2cPrefix }, fetchImpl);
    }

    /**
     * Sends a sealed request to the enclave. `path` must include a leading
     * slash and any query string. `body` is encoded as JSON if it is not
     * already a Uint8Array / string.
     */
    async request(method: string, path: string, body?: unknown, init?: RequestInit): Promise<SealedResponse> {
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

        const url = `https://${this.host}${path}`;
        const resp = await this.fetchImpl(url, {
            ...init,
            method: upperMethod,
            headers,
            body: reqBody as BodyInit,
        });

        const respBody = new Uint8Array(await resp.arrayBuffer());
        // Allow plaintext error responses (e.g. 502 from the gateway with no
        // session-relay context). The caller can branch on status + sealed.
        if (!resp.headers.get('content-type')?.startsWith(SEALED_CONTENT_TYPE)) {
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

    /** Convenience for JSON responses. */
    async json<T = unknown>(method: string, path: string, body?: unknown, init?: RequestInit): Promise<T> {
        const r = await this.request(method, path, body, init);
        if (r.status >= 400) {
            throw new Error(`PrivasysSession ${method} ${path}: ${r.status}`);
        }
        return JSON.parse(new TextDecoder().decode(r.body)) as T;
    }
}

export interface SealedResponse {
    status: number;
    /** True if the response body has been decrypted; false for raw passthrough (gateway 5xx). */
    sealed: boolean;
    body: Uint8Array;
    headers: Headers;
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

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

function concat(parts: Uint8Array[]): Uint8Array {
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
