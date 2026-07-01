// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.
//
// Known-answer test for the session-relay crypto contract (§9),
// cross-checking the TS/WebCrypto implementation against the Go
// reference vectors pinned in
// enclave-os-virtual/internal/sessionrelay/kats_test.go.
//
// Run with:  npm run build && node scripts/kat.mjs
//
// Exercises the REAL production path end-to-end: JWK key import →
// PrivasysSession.fromHandshake (ECDH + HKDF + prefix derivation) →
// request() (AEAD seal + CBOR envelope, captured via fetchImpl) →
// response unsealing of a Go-produced envelope.

import { webcrypto as crypto } from 'node:crypto';
import { createHash } from 'node:crypto';
import { PrivasysSession } from '../dist/enclave-session.js';

// ── Pinned vectors (Go reference) ───────────────────────────────────

const SESSION_ID_RAW_HEX = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
const SDK_PUB_HEX =
    '04e36eef3794039af0273a59831da695cef92dfeee2d4a4b24e08d5d35aed2f8f877b9a7527733910e82f88a86afa506a47a245a86a2b95d3722c28d8f1ac6bfb4';
const ENC_PUB_HEX =
    '04dd511dcde3875568de732fde5634d8940b5bcfef668ace46f28bd813a27eb6af695e2fe52acb03f4d158a46335e0a726765540290c28614379953e1ab483d924';
const REQUEST_PT = '{"kat":"privasys-session-relay"}';
const RESPONSE_PT = '{"ok":true}';
const PATH = '/v1/chat/completions';
const REQUEST_ENV_HEX =
    'a361760163637472006263745830f6868ef8c27ae5260300135329bbbb941825c36ec5b29143df5110e64cc42a98a26521ac449d50153594ffcfd35f7f92';
const RESPONSE_ENV_HEX =
    'a36176016363747200626374581b27445f008c6ee1a871bff6df237343c1fde2cec805bc23ca31c59c';

// ── Helpers ─────────────────────────────────────────────────────────

const hexToBytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const b64u = (b) => Buffer.from(b).toString('base64url');

function fail(msg) {
    console.error(`KAT FAIL: ${msg}`);
    process.exit(1);
}

function assertEq(name, gotHex, wantHex) {
    if (gotHex !== wantHex) {
        fail(`${name} mismatch:\n  got  ${gotHex}\n  want ${wantHex}`);
    }
    console.log(`  ok: ${name}`);
}

// ── Main ────────────────────────────────────────────────────────────

// Deterministic SDK scalar per the spec: SHA-256("privasys-kat-sdk/v1").
const d = createHash('sha256').update('privasys-kat-sdk/v1').digest();
const sdkPub = hexToBytes(SDK_PUB_HEX);

const sdkPrivateKey = await crypto.subtle.importKey(
    'jwk',
    {
        kty: 'EC',
        crv: 'P-256',
        d: b64u(d),
        x: b64u(sdkPub.subarray(1, 33)),
        y: b64u(sdkPub.subarray(33, 65)),
    },
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
);

const sessionId = b64u(hexToBytes(SESSION_ID_RAW_HEX));

let capturedRequestBody = null;
const fetchImpl = async (url, init) => {
    capturedRequestBody = new Uint8Array(init.body);
    if (init.headers.get('Authorization') !== `PrivasysSession ${sessionId}`) {
        fail(`unexpected Authorization header: ${init.headers.get('Authorization')}`);
    }
    if (!url.endsWith(PATH)) fail(`unexpected URL: ${url}`);
    // Reply with the Go-sealed response envelope.
    return new Response(hexToBytes(RESPONSE_ENV_HEX), {
        status: 200,
        headers: { 'Content-Type': 'application/privasys-sealed+cbor' },
    });
};

const session = await PrivasysSession.fromHandshake({
    host: 'kat.invalid',
    sessionId,
    sdkPrivateKey,
    encPub: b64u(hexToBytes(ENC_PUB_HEX)),
    fetchImpl,
});

// Pass the plaintext as a string so the bytes on the wire are exactly
// REQUEST_PT (objects would be re-serialised).
const resp = await session.request('POST', PATH, REQUEST_PT);

assertEq('request envelope', bytesToHex(capturedRequestBody), REQUEST_ENV_HEX);
if (!resp.sealed || resp.status !== 200) {
    fail(`response not sealed/200: sealed=${resp.sealed} status=${resp.status}`);
}
assertEq(
    'response plaintext',
    Buffer.from(resp.body).toString('utf8'),
    RESPONSE_PT,
);

// ── Regression guard: EncAuth resume must pin the response enc_pub to
//    the voucher's bound enc_pub (security review finding 1). A bootstrap
//    response that substitutes a different enc_pub must be REJECTED so a
//    gateway/MITM cannot key the "sealed" session to itself. ────────────
{
    const encPriv = createHash('sha256').update('privasys-kat-enc/v1').digest();
    const encPub = hexToBytes(ENC_PUB_HEX);
    // Minimal canonical-CBOR EncAuth payload (map(10)) binding the genuine
    // enc_pub at key 6; other fields are placeholders (the SDK only reads
    // key 6 for pinning).
    const cbor = [];
    const bstr = (b) => { cbor.push(0x58, b.length); for (const x of b) cbor.push(x); };
    const tstr = (s) => { const e = Buffer.from(s); cbor.push(0x60 | e.length); for (const x of e) cbor.push(x); };
    cbor.push(0xaa);
    cbor.push(0x01, 0x01);                 // 1 v=1
    cbor.push(0x02); tstr('u');            // 2 sub
    cbor.push(0x03); tstr('s');            // 3 sid
    cbor.push(0x04); bstr(new Uint8Array(32)); // 4 app_id
    cbor.push(0x05); bstr(new Uint8Array(32)); // 5 enc_meas
    cbor.push(0x06); bstr(encPub);         // 6 enc_pub (genuine)
    cbor.push(0x07); bstr(new Uint8Array(32)); // 7 quote_hash
    cbor.push(0x08, 0x00);                 // 8 not_before
    cbor.push(0x09, 0x1b, 0,0,0,0, 0xee,0x6b,0x28,0x00); // 9 not_after far future
    cbor.push(0x0a); bstr(new Uint8Array(65).fill(0x04)); // 10 hw_pub
    const voucher = { v: 1, payload: Buffer.from(cbor).toString('base64url'), hw_sig: '', idp_sig: '' };

    // A "malicious enclave" keypair whose enc_pub differs from the voucher.
    const evil = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const evilPub = new Uint8Array(await crypto.subtle.exportKey('raw', evil.publicKey));

    const sub = { count: 0 };
    const evilFetch = async (url, init) => {
        if (url.endsWith('/__privasys/session-bootstrap')) {
            sub.count++;
            // NB: includes `sub` — the bootstrap response crosses the
            // terminate leg in the clear, so a MITM can inject any subject.
            // Passing the voucher-consumed gate here keeps this KAT proving
            // the enc_pub PIN is what rejects the substitution.
            return new Response(
                JSON.stringify({ session_id: b64u(hexToBytes(SESSION_ID_RAW_HEX)), enc_pub: b64u(evilPub), sub: 'u' }),
                { status: 200, headers: { 'Content-Type': 'application/json' } },
            );
        }
        fail(`unexpected fetch to ${url}`);
    };

    const r = await PrivasysSession.resume({
        host: 'evil.invalid',
        getEncAuth: async () => voucher,
        fetchImpl: evilFetch,
    });
    if (!('error' in r)) fail('resume accepted a substituted enc_pub — gateway could read sealed traffic');
    if (sub.count === 0) fail('resume never reached the bootstrap call');
    console.log(`  ok: substituted enc_pub rejected (error=${r.error})`);
}

console.log('session-relay KATs: TS/WebCrypto matches the Go reference; enc_pub pinning holds.');
