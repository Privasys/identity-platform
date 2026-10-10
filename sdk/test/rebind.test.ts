// Silent rebind on an unsealed 401: every request that hits it at the same
// moment must share ONE voucher-backed bootstrap (the enclave budgets them
// per session), and the session must report its liveness while doing so.
// Runs under `node --test` with Node's WebCrypto and Response globals.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PrivasysSession, type EncAuthEnvelope, type SealedSessionState } from '../src/enclave-session';

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');

/** A P-256 keypair the enclave side would hold (its enc_pub). */
async function encKey(): Promise<{ priv: CryptoKey; pubRaw: Uint8Array }> {
    const kp = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair;
    return { priv: kp.privateKey, pubRaw: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)) };
}

/** Minimal EncAuth payload: CBOR map(10) with enc_pub at key 6 (what the
 *  SDK pins the bootstrap response against); every other value is 0. */
function voucherFor(encPub: Uint8Array): EncAuthEnvelope {
    const out: number[] = [0xaa];
    for (let k = 0; k < 10; k++) {
        out.push(k);
        if (k === 6) out.push(0x58, encPub.byteLength, ...encPub);
        else out.push(0x00);
    }
    return { v: 1, payload: b64u(new Uint8Array(out)), hw_sig: '', idp_sig: '' };
}

test('parallel unsealed 401s share one rebind and report liveness', async () => {
    const enclave = await encKey();
    const sdk = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])) as CryptoKeyPair;
    const sessionId = b64u(crypto.getRandomValues(new Uint8Array(16)));

    let bootstraps = 0;
    const fetchImpl: typeof fetch = async (input) => {
        const url = String(input);
        if (url.endsWith('/__privasys/session-bootstrap')) {
            bootstraps++;
            await new Promise((r) => setTimeout(r, 20)); // let the others pile up
            return new Response(
                JSON.stringify({ session_id: b64u(crypto.getRandomValues(new Uint8Array(16))), enc_pub: b64u(enclave.pubRaw), sub: 'holder-1' }),
                { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
        }
        // The enclave forgot the session: an UNSEALED 401, every time.
        return new Response('unknown or expired session', { status: 401, headers: { 'Content-Type': 'text/plain' } });
    };

    const session = await PrivasysSession.fromHandshake({
        host: 'app.example.test',
        sessionId,
        sdkPrivateKey: sdk.privateKey,
        encPub: b64u(enclave.pubRaw),
        fetchImpl,
        getEncAuth: async () => voucherFor(enclave.pubRaw),
    });
    const states: SealedSessionState[] = [];
    session.onStateChange = (s) => states.push(s);

    const before = session.sessionId;
    const results = await Promise.all([
        session.request('GET', '/api/one'),
        session.request('GET', '/api/two'),
        session.request('GET', '/api/three'),
    ]);

    assert.equal(bootstraps, 1, 'three concurrent 401s must cost one bootstrap');
    assert.notEqual(session.sessionId, before, 'the session adopted the rebound id');
    for (const r of results) assert.equal(r.status, 401); // still 401 here: the stub never recovers
    assert.deepEqual(states.map((s) => s.status), ['recovering', 'ok']);
});

test('a refused voucher reports reapproval-required with the reason', async () => {
    const enclave = await encKey();
    const sdk = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])) as CryptoKeyPair;
    const fetchImpl: typeof fetch = async (input) => {
        if (String(input).endsWith('/__privasys/session-bootstrap')) {
            return new Response(
                JSON.stringify({ session_id: 'x', enc_pub: b64u(enclave.pubRaw), encauth_reject: 'workload-changed' }),
                { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
        }
        return new Response('unknown or expired session', { status: 401 });
    };
    const session = await PrivasysSession.fromHandshake({
        host: 'app.example.test',
        sessionId: b64u(crypto.getRandomValues(new Uint8Array(16))),
        sdkPrivateKey: sdk.privateKey,
        encPub: b64u(enclave.pubRaw),
        fetchImpl,
        getEncAuth: async () => voucherFor(enclave.pubRaw),
    });
    const states: SealedSessionState[] = [];
    session.onStateChange = (s) => states.push(s);
    const r = await session.request('GET', '/api/one');
    assert.equal(r.status, 401);
    assert.deepEqual(states, [
        { status: 'recovering' },
        { status: 'reapproval-required', reason: 'workload-changed' },
    ]);
});

/** The sealed reply an enclave sends: CBOR map {v, ctr, ct}. */
function sealedEnvelope(ctr: number, ct: Uint8Array): Uint8Array {
    const text = (s: string) => [0x60 + s.length, ...new TextEncoder().encode(s)];
    const bytes = ct.byteLength < 24 ? [0x40 + ct.byteLength] : [0x58, ct.byteLength];
    return new Uint8Array([0xa3, ...text('v'), 0x01, ...text('ctr'), ctr, ...text('ct'), ...bytes, ...ct]);
}

test('a reply sealed before a concurrent rebind still opens', async () => {
    const enclave = await encKey();
    const sdk = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])) as CryptoKeyPair;
    const sessionId = b64u(crypto.getRandomValues(new Uint8Array(16)));

    let rebound!: () => void;
    const reboundDone = new Promise<void>((r) => (rebound = r));
    let original: { aead: CryptoKey; s2cPrefix: Uint8Array } | undefined;

    const fetchImpl: typeof fetch = async (input) => {
        const url = String(input);
        if (url.endsWith('/__privasys/session-bootstrap')) {
            setTimeout(rebound, 0);
            return new Response(
                JSON.stringify({ session_id: b64u(crypto.getRandomValues(new Uint8Array(16))), enc_pub: b64u(enclave.pubRaw), sub: 'holder-1' }),
                { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
        }
        if (url.endsWith('/api/slow')) {
            // Answered by the session it was sent on, but only after another
            // request has rebound the session in place.
            await reboundDone;
            const nonce = new Uint8Array(12);
            nonce.set(original!.s2cPrefix.subarray(0, 4), 0);
            new DataView(nonce.buffer).setBigUint64(4, 0n, false);
            const ad = new TextEncoder().encode(`GET:/api/slow:${sessionId}`);
            const ct = new Uint8Array(await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce, additionalData: ad }, original!.aead, new TextEncoder().encode('{"ok":true}')));
            return new Response(sealedEnvelope(0, ct), { status: 200, headers: { 'Content-Type': 'application/privasys-sealed+cbor' } });
        }
        // Any other request finds the session forgotten (the enclave restarted).
        return new Response('unknown or expired session', { status: 401, headers: { 'Content-Type': 'text/plain' } });
    };

    const session = await PrivasysSession.fromHandshake({
        host: 'app.example.test',
        sessionId,
        sdkPrivateKey: sdk.privateKey,
        encPub: b64u(enclave.pubRaw),
        fetchImpl,
        getEncAuth: async () => voucherFor(enclave.pubRaw),
    });
    original = (session as unknown as { keys: { aead: CryptoKey; s2cPrefix: Uint8Array } }).keys;

    const slow = session.request('GET', '/api/slow');
    await session.request('GET', '/api/fast'); // rebinds the session in place
    assert.notEqual(session.sessionId, sessionId, 'the session rebound while /api/slow was in flight');
    const r = await slow;
    assert.equal(r.status, 200);
    assert.equal(new TextDecoder().decode(r.body), '{"ok":true}');
});

test('a late 401 from a session already rebound retries without a second bootstrap', async () => {
    const enclave = await encKey();
    const sdk = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])) as CryptoKeyPair;
    const sessionId = b64u(crypto.getRandomValues(new Uint8Array(16)));

    let bootstraps = 0;
    let rebound!: () => void;
    const reboundDone = new Promise<void>((r) => (rebound = r));
    const live = new Set<string>();

    const fetchImpl: typeof fetch = async (input, init) => {
        const url = String(input);
        if (url.endsWith('/__privasys/session-bootstrap')) {
            bootstraps++;
            const id = b64u(crypto.getRandomValues(new Uint8Array(16)));
            live.add(id);
            setTimeout(rebound, 0);
            return new Response(
                JSON.stringify({ session_id: id, enc_pub: b64u(enclave.pubRaw), sub: 'holder-1' }),
                { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
        }
        const auth = new Headers(init?.headers).get('Authorization') ?? '';
        const onSession = auth.split(' ')[1] ?? '';
        if (url.endsWith('/api/slow') && onSession === sessionId) {
            // The enclave restarted: this request on the first session is
            // refused, but only after another request has rebound it.
            await reboundDone;
            return new Response('unknown or expired session', { status: 401, headers: { 'Content-Type': 'text/plain' } });
        }
        if (live.has(onSession)) {
            // A live session's reply; the test only checks the status.
            return new Response(null, { status: 204 });
        }
        return new Response('unknown or expired session', { status: 401, headers: { 'Content-Type': 'text/plain' } });
    };

    const session = await PrivasysSession.fromHandshake({
        host: 'app.example.test',
        sessionId,
        sdkPrivateKey: sdk.privateKey,
        encPub: b64u(enclave.pubRaw),
        fetchImpl,
        getEncAuth: async () => voucherFor(enclave.pubRaw),
    });

    const slow = session.request('GET', '/api/slow');
    const fast = await session.request('GET', '/api/fast'); // rebinds the session in place
    assert.equal(fast.status, 204);
    assert.equal(bootstraps, 1);
    const r = await slow;
    assert.equal(r.status, 204, 'the straggler was retried on the live session');
    assert.equal(bootstraps, 1, 'its late 401 did not start a second bootstrap');
});
