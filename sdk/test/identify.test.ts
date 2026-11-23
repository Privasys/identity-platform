// An anonymous session (the wallet's own bootstrap, which tells the enclave
// nothing about the caller) becomes an identified one from the wallet's
// voucher: when asked, and when the app answers it 401. Runs under
// `node --test` with Node's WebCrypto and Response globals.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PrivasysSession, type EncAuthEnvelope } from '../src/enclave-session';

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');

async function encKey(): Promise<{ pubRaw: Uint8Array }> {
    const kp = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair;
    return { pubRaw: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)) };
}

/** Minimal EncAuth payload: CBOR map(10) with enc_pub at key 6. */
function voucherFor(encPub: Uint8Array): EncAuthEnvelope {
    const out: number[] = [0xaa];
    for (let k = 0; k < 10; k++) {
        out.push(k);
        if (k === 6) out.push(0x58, encPub.byteLength, ...encPub);
        else out.push(0x00);
    }
    return { v: 1, payload: b64u(new Uint8Array(out)), hw_sig: '', idp_sig: '' };
}

function sealedEnvelope(ctr: number, ct: Uint8Array): Uint8Array {
    const text = (s: string) => [0x60 + s.length, ...new TextEncoder().encode(s)];
    const bytes = ct.byteLength < 24 ? [0x40 + ct.byteLength] : [0x58, ct.byteLength];
    return new Uint8Array([0xa3, ...text('v'), 0x01, ...text('ctr'), ctr, ...text('ct'), ...bytes, ...ct]);
}

type Keys = { aead: CryptoKey; s2cPrefix: Uint8Array };
const keysOf = (s: PrivasysSession) => (s as unknown as { keys: Keys }).keys;

/** An app that answers 401 to an anonymous session and 200 to an identified
 *  one, sealed under whichever session the request came on. */
async function setup(opts: { voucher: () => boolean }) {
    const enclave = await encKey();
    const sdk = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])) as CryptoKeyPair;
    const anonymousId = b64u(crypto.getRandomValues(new Uint8Array(16)));
    let bootstraps = 0;
    let appCalls = 0;
    const ctrs = new Map<string, number>();
    let session!: PrivasysSession;

    const fetchImpl: typeof fetch = async (input, init) => {
        const url = new URL(String(input));
        if (url.pathname === '/__privasys/session-bootstrap') {
            bootstraps++;
            return new Response(
                JSON.stringify({ session_id: b64u(crypto.getRandomValues(new Uint8Array(16))), enc_pub: b64u(enclave.pubRaw), sub: 'holder-1' }),
                { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
        }
        appCalls++;
        const sid = new Headers(init?.headers).get('Authorization')!.replace('PrivasysSession ', '');
        const identified = sid !== anonymousId;
        const keys = keysOf(session);
        const ctr = ctrs.get(sid) ?? 0;
        ctrs.set(sid, ctr + 1);
        const nonce = new Uint8Array(12);
        nonce.set(keys.s2cPrefix.subarray(0, 4), 0);
        new DataView(nonce.buffer).setBigUint64(4, BigInt(ctr), false);
        const ad = new TextEncoder().encode(`${init?.method}:${url.pathname}:${sid}`);
        const pt = new TextEncoder().encode(identified ? '{"ok":true}' : 'authentication required');
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: ad }, keys.aead, pt));
        return new Response(sealedEnvelope(ctr, ct), {
            status: 200,
            headers: { 'Content-Type': 'application/privasys-sealed+cbor', 'X-Privasys-Inner-Status': identified ? '200' : '401' },
        });
    };

    session = await PrivasysSession.fromHandshake({
        host: 'app.example.test',
        sessionId: anonymousId,
        sdkPrivateKey: sdk.privateKey,
        encPub: b64u(enclave.pubRaw),
        fetchImpl,
        getEncAuth: async () => (opts.voucher() ? voucherFor(enclave.pubRaw) : null),
        anonymous: true,
    });
    return { session, anonymousId, counts: () => ({ bootstraps, appCalls }) };
}

test("an app's 401 to an anonymous session identifies it and retries once", async () => {
    const { session, anonymousId, counts } = await setup({ voucher: () => true });
    assert.equal(session.isAnonymous, true);
    const r = await session.request('GET', '/api/me');
    assert.equal(r.status, 200);
    assert.equal(new TextDecoder().decode(r.body), '{"ok":true}');
    assert.equal(session.isAnonymous, false);
    assert.notEqual(session.sessionId, anonymousId);
    assert.deepEqual(counts(), { bootstraps: 1, appCalls: 2 });
});

test('without a voucher yet, the 401 stands and the session stays usable', async () => {
    let ready = false;
    const { session, counts } = await setup({ voucher: () => ready });
    const first = await session.request('GET', '/api/me');
    assert.equal(first.status, 401);
    assert.equal(session.isAnonymous, true);
    assert.deepEqual(counts(), { bootstraps: 0, appCalls: 1 });
    // The voucher lands: the next 401 picks it up.
    ready = true;
    const second = await session.request('GET', '/api/me');
    assert.equal(second.status, 200);
    assert.equal(session.isAnonymous, false);
});

test('identify() in the background identifies once, and parallel calls share it', async () => {
    const { session, counts } = await setup({ voucher: () => true });
    const results = await Promise.all([session.identify(), session.identify(), session.identify()]);
    assert.deepEqual(results, [true, true, true]);
    assert.equal(counts().bootstraps, 1);
    const r = await session.request('GET', '/api/me');
    assert.equal(r.status, 200);
    assert.deepEqual(counts(), { bootstraps: 1, appCalls: 1 });
});

test('an identified session never re-identifies on an app 401', async () => {
    // A session that started identified: the app's 401 is the app's answer.
    const { session, counts } = await setup({ voucher: () => true });
    await session.identify();
    const before = counts().bootstraps;
    assert.equal(await session.identify(), true);
    assert.equal(counts().bootstraps, before);
});
