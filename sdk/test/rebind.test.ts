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
