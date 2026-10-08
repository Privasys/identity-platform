// A sealed WebSocket the enclave refuses because it forgot the session is the
// socket-shaped unsealed 401: the SDK must rebind (sharing the coalesced
// rebind) and re-open the SAME socket object on the new session, with queued
// sends intact, so socket-only apps recover the way request-only apps do.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PrivasysSession, type EncAuthEnvelope, type SealedSessionState } from '../src/enclave-session';

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const fromB64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

function voucherFor(encPub: Uint8Array): EncAuthEnvelope {
    const out: number[] = [0xaa];
    for (let k = 0; k < 10; k++) {
        out.push(k);
        if (k === 6) out.push(0x58, encPub.byteLength, ...encPub);
        else out.push(0x00);
    }
    return { v: 1, payload: b64u(new Uint8Array(out)), hw_sig: '', idp_sig: '' };
}

/** The enclave side of one stream: derive the keys the SDK will derive and
 *  seal the stream ack (s2c ctr 0, plaintext "ack"). */
async function sealAck(enclavePriv: CryptoKey, sdkPubRaw: Uint8Array, sessionId: string, path: string, streamHex: string): Promise<Uint8Array> {
    const sdkPub = await crypto.subtle.importKey('raw', sdkPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: sdkPub }, enclavePriv, 256);
    const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const salt = fromB64u(sessionId);
    const enc = new TextEncoder();
    const hkdf = (info: string, bits: number) =>
        crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, ikm, bits);
    const aead = await crypto.subtle.importKey('raw', await hkdf('privasys-session/v1', 256), { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const prefix = new Uint8Array(await hkdf(`privasys-dir/ws-s2c/${streamHex}`, 32));
    const nonce = new Uint8Array(12);
    nonce.set(prefix, 0); // ctr 0 → trailing 8 bytes stay zero
    const ad = enc.encode(`WS:${path}:${sessionId}:${streamHex}`);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: ad }, aead, enc.encode('ack')));
    // CBOR {v:1, ctr:0, ct:<bytes>} with a one-byte length (ct is 19 bytes).
    return new Uint8Array([0xa3, 0x61, 0x76, 0x01, 0x63, 0x63, 0x74, 0x72, 0x00, 0x62, 0x63, 0x74, 0x58, ct.byteLength, ...ct]);
}

/** A scripted WebSocket: the first instance is refused by the enclave, the
 *  second opens and acks the stream. */
class FakeSocket {
    static instances: FakeSocket[] = [];
    static onOpenSecond?: (ws: FakeSocket) => void;
    readyState = 0;
    protocol = '';
    binaryType = '';
    onopen: (() => void) | null = null;
    onmessage: ((ev: { data: ArrayBuffer }) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: ((ev: { code: number; reason: string; wasClean: boolean }) => void) | null = null;
    sent: Uint8Array[] = [];
    constructor(public url: string, public protocols: string[]) {
        FakeSocket.instances.push(this);
        const n = FakeSocket.instances.length;
        setTimeout(() => {
            if (n === 1) {
                this.readyState = 3;
                this.onclose?.({ code: 1008, reason: 'unknown or expired session', wasClean: true });
            } else {
                this.readyState = 1;
                this.protocol = 'privasys.sealed.v1';
                this.onopen?.();
            }
        }, 5);
    }
    send(data: ArrayBuffer) {
        this.sent.push(new Uint8Array(data));
        FakeSocket.onOpenSecond?.(this);
    }
    close() { this.readyState = 3; }
}

test('a socket refused for a forgotten session rebinds and re-opens on the new session', async () => {
    const enclave = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair;
    const encPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', enclave.publicKey));
    const sdk = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair;

    let bootstraps = 0;
    let reboundSdkPub: Uint8Array | null = null;
    const newSessionId = b64u(crypto.getRandomValues(new Uint8Array(16)));
    const fetchImpl: typeof fetch = async (input, init) => {
        if (String(input).endsWith('/__privasys/session-bootstrap')) {
            bootstraps++;
            const body = JSON.parse(String(init?.body)) as { sdk_pub: string };
            reboundSdkPub = fromB64u(body.sdk_pub);
            return new Response(JSON.stringify({ session_id: newSessionId, enc_pub: b64u(encPubRaw), sub: 'holder-1' }), {
                status: 200, headers: { 'Content-Type': 'application/json' },
            });
        }
        return new Response('unknown or expired session', { status: 401 });
    };

    const firstSessionId = b64u(crypto.getRandomValues(new Uint8Array(16)));
    const session = await PrivasysSession.fromHandshake({
        host: 'app.example.test',
        sessionId: firstSessionId,
        sdkPrivateKey: sdk.privateKey,
        encPub: b64u(encPubRaw),
        fetchImpl,
        getEncAuth: async () => voucherFor(encPubRaw),
    });
    const states: SealedSessionState[] = [];
    session.onStateChange = (s) => states.push(s);

    // When the second socket receives the SDK's stream open, answer with the
    // enclave's sealed ack for THAT stream on the NEW session.
    FakeSocket.onOpenSecond = (ws) => {
        if (ws !== FakeSocket.instances[1] || ws.sent.length !== 1) return;
        void sealAck(enclave.privateKey, reboundSdkPub!, newSessionId, '/events', ws.protocols[2]).then((ack) => {
            ws.onmessage?.({ data: ack.buffer.slice(ack.byteOffset, ack.byteOffset + ack.byteLength) as ArrayBuffer });
        });
    };

    const ws = session.openWebSocket('/events', { WebSocketImpl: FakeSocket as unknown as typeof WebSocket });
    ws.send('queued before the refusal'); // must survive the re-open
    await ws.ready;

    assert.equal(bootstraps, 1, 'one rebind');
    assert.equal(FakeSocket.instances.length, 2, 'the socket re-opened once');
    assert.equal(FakeSocket.instances[0].protocols[1], firstSessionId);
    assert.equal(FakeSocket.instances[1].protocols[1], newSessionId, 're-opened on the rebound session');
    assert.notEqual(FakeSocket.instances[1].protocols[2], FakeSocket.instances[0].protocols[2], 'fresh stream id');
    assert.equal(session.sessionId, newSessionId);
    assert.deepEqual(states.map((s) => s.status), ['recovering', 'ok']);
    // The queued send went out on the new socket after the stream open.
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(FakeSocket.instances[1].sent.length, 2, 'stream open + the queued message');
    assert.equal(FakeSocket.instances[0].sent.length, 0, 'nothing was sent on the refused socket');
});
