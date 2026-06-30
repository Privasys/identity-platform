// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * EncAuth voucher builder + uploader.
 *
 * Implements the wallet half of the silent-rebind voucher.
 *
 * Flow:
 *   1. Wallet collects attestation OIDs + enclave public key + leaf
 *      cert hash from a verified RA-TLS exchange (already done during
 *      session-relay sign-in).
 *   2. `buildEncAuthPayload()` packs the fields into canonical CBOR.
 *   3. `signAndUploadEncAuth()` asks the hardware-backed key to sign
 *      the canonical bytes, converts the DER signature to fixed
 *      64-byte R||S, and PUTs `{payload, hw_sig}` to the IdP.
 *   4. The IdP verifies hw_sig, co-signs `payload || hw_sig` with its
 *      OIDC ES256 key, and stores the envelope on the session row.
 *
 * The signature scheme matches WebCrypto/`ecdsa.SigningMethodES256`
 * exactly (P-256 + SHA-256, fixed 64-byte R||S).
 */

import { bytesToBase64url as b64uEncode, base64urlToBytes as b64uDecode } from '@/utils/encoding';

import * as NativeKeys from '../../modules/native-keys/src/index';

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

import { encMeasHash, workloadDigestHash } from './oid-digest';

const IDP_BASE_URL = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

// ---- canonical CBOR encoder (RFC 8949 §4.2.1) -----------------------
//
// Only emits the subset we need: positive integers, byte strings, and
// text strings, plus a deterministic map with integer keys 1..23.

function encUint(n: number | bigint): Uint8Array {
    const v = typeof n === 'bigint' ? n : BigInt(n);
    if (v < 0n) throw new Error('encUint: negative');
    if (v < 24n) return new Uint8Array([Number(v)]);
    if (v < 0x100n) return new Uint8Array([0x18, Number(v)]);
    if (v < 0x10000n) {
        return new Uint8Array([0x19, Number((v >> 8n) & 0xffn), Number(v & 0xffn)]);
    }
    if (v < 0x100000000n) {
        const out = new Uint8Array(5);
        out[0] = 0x1a;
        out[1] = Number((v >> 24n) & 0xffn);
        out[2] = Number((v >> 16n) & 0xffn);
        out[3] = Number((v >> 8n) & 0xffn);
        out[4] = Number(v & 0xffn);
        return out;
    }
    // 64-bit
    const out = new Uint8Array(9);
    out[0] = 0x1b;
    for (let i = 0; i < 8; i++) out[8 - i] = Number((v >> BigInt(i * 8)) & 0xffn);
    return out;
}

function withMajor(major: number, lengthBytes: Uint8Array): Uint8Array {
    // lengthBytes was built by encUint with major-type=0 in its high
    // bits. OR in the requested major type instead.
    const out = new Uint8Array(lengthBytes);
    out[0] = (out[0] & 0x1f) | (major << 5);
    return out;
}

function encBstr(b: Uint8Array): Uint8Array {
    const head = withMajor(2, encUint(b.length));
    const out = new Uint8Array(head.length + b.length);
    out.set(head, 0);
    out.set(b, head.length);
    return out;
}

function encTstr(s: string): Uint8Array {
    const bytes = new TextEncoder().encode(s);
    const head = withMajor(3, encUint(bytes.length));
    const out = new Uint8Array(head.length + bytes.length);
    out.set(head, 0);
    out.set(bytes, head.length);
    return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }
    return out;
}

/**
 * EncAuth payload as defined in crypto-contract.md §8.1.
 *
 * All byte arrays must be raw bytes (NOT base64). hwPub and encPub
 * MUST be P-256 SEC1 uncompressed (65 bytes starting with 0x04).
 * workloadDigest, encMeas, quoteHash MUST be SHA-256 outputs (32 bytes each).
 *
 * `workloadDigest` is CBOR key 4 (named `app_id` in the wire format /
 * crypto-contract §8.1). It is NOT the static OID 3.6 app-id; it is the
 * workload-measurement digest over OIDs 3.1/3.2/3.3/3.4 (see
 * workloadDigestHash), so it moves with the OID 3.2 code hash.
 */
export interface EncAuthPayload {
    sub: string;
    sid: string;
    workloadDigest: Uint8Array;
    encMeas: Uint8Array;
    encPub: Uint8Array;
    quoteHash: Uint8Array;
    notBefore: number; // unix seconds
    notAfter: number;  // unix seconds
    hwPub: Uint8Array;
}

/**
 * Build the canonical CBOR encoding of an EncAuth payload.
 *
 * Map keys are integer-tagged (1=v, 2=sub, 3=sid, 4=workload_digest,
 * 5=enc_meas, 6=enc_pub, 7=quote_hash, 8=not_before, 9=not_after,
 * 10=hw_pub) and emitted in ascending order, matching the IdP/enclave
 * canonical encoder. The output bytes are signed verbatim (no
 * base64) by `signEncAuth()`.
 */
export function buildEncAuthPayload(p: EncAuthPayload): Uint8Array {
    if (p.workloadDigest.length !== 32) throw new Error('workload_digest must be 32 bytes');
    if (p.encMeas.length !== 32) throw new Error('enc_meas must be 32 bytes');
    if (p.quoteHash.length !== 32) throw new Error('quote_hash must be 32 bytes');
    if (p.encPub.length !== 65 || p.encPub[0] !== 0x04) {
        throw new Error('enc_pub must be P-256 SEC1 uncompressed');
    }
    if (p.hwPub.length !== 65 || p.hwPub[0] !== 0x04) {
        throw new Error('hw_pub must be P-256 SEC1 uncompressed');
    }

    // Map header for 10 entries.
    const mapHeader = withMajor(5, encUint(10));
    const entries = [
        concat([encUint(1), encUint(1)]),
        concat([encUint(2), encTstr(p.sub)]),
        concat([encUint(3), encTstr(p.sid)]),
        concat([encUint(4), encBstr(p.workloadDigest)]),
        concat([encUint(5), encBstr(p.encMeas)]),
        concat([encUint(6), encBstr(p.encPub)]),
        concat([encUint(7), encBstr(p.quoteHash)]),
        concat([encUint(8), encUint(p.notBefore)]),
        concat([encUint(9), encUint(p.notAfter)]),
        concat([encUint(10), encBstr(p.hwPub)]),
    ];
    return concat([mapHeader, ...entries]);
}

// ---- DER → fixed 64-byte R||S ---------------------------------------

/**
 * Convert an ASN.1 DER ECDSA signature (as returned by the platform
 * crypto APIs and `@privasys/native-keys`) into the fixed 64-byte
 * R||S form expected by EncAuth and by WebCrypto verification.
 *
 * Layout:  30 LL  02 RL <R…>  02 SL <S…>
 * Both R and S are zero-padded (or trimmed of a leading 0x00
 * sign-extension byte) to exactly 32 bytes.
 */
export function derToRawEcdsa(der: Uint8Array): Uint8Array {
    if (der.length < 8 || der[0] !== 0x30) throw new Error('not a DER sequence');
    let off = 2;
    if ((der[1] ?? 0) & 0x80) {
        // Long-form length: skip the length-of-length bytes.
        off = 2 + ((der[1] ?? 0) & 0x7f);
    }
    if (der[off] !== 0x02) throw new Error('expected INTEGER for R');
    const rLen = der[off + 1] ?? 0;
    let rStart = off + 2;
    let rEnd = rStart + rLen;
    // Trim leading 0x00 sign byte if present.
    if (der[rStart] === 0x00 && rLen === 33) rStart += 1;

    let sOff = rEnd;
    if (der[sOff] !== 0x02) throw new Error('expected INTEGER for S');
    const sLen = der[sOff + 1] ?? 0;
    let sStart = sOff + 2;
    const sEnd = sStart + sLen;
    if (der[sStart] === 0x00 && sLen === 33) sStart += 1;

    const out = new Uint8Array(64);
    const r = der.subarray(rStart, rEnd);
    const s = der.subarray(sStart, sEnd);
    out.set(r, 32 - r.length);
    out.set(s, 64 - s.length);
    return out;
}

// ---- base64url helpers ----------------------------------------------

function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) throw new Error('hexToBytes: odd length');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        const byte = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        if (Number.isNaN(byte)) throw new Error('hexToBytes: invalid hex');
        out[i] = byte;
    }
    return out;
}

// ---- sign + upload --------------------------------------------------

export interface EncAuthEnvelope {
    v: 1;
    payload: string;        // base64url(canonical CBOR)
    hw_sig: string;         // base64url(64 B R||S)
    idp_sig?: string;       // base64url(64 B R||S), set after IdP co-signs
}

/**
 * Sign an EncAuth payload using a hardware-backed key.
 *
 * Returns the canonical CBOR bytes alongside the 64-byte R||S
 * signature, ready to upload.
 */
export async function signEncAuth(
    keyId: string,
    payload: EncAuthPayload,
): Promise<{ payload: Uint8Array; hwSig: Uint8Array }> {
    const cborBytes = buildEncAuthPayload(payload);
    const result = await NativeKeys.sign(keyId, b64uEncode(cborBytes));
    const der = b64uDecode(result.signature);
    const hwSig = derToRawEcdsa(der);
    if (hwSig.length !== 64) throw new Error('hw_sig must be 64 bytes');
    return { payload: cborBytes, hwSig };
}

/**
 * Upload a signed EncAuth payload to the IdP.
 *
 * `walletSessionToken` is the opaque wallet-session token issued by
 * the FIDO2 register/authenticate flow — sent as
 * `Authorization: Bearer wallet:<token>`. The IdP verifies hw_sig,
 * co-signs, and returns the full envelope.
 */
export async function uploadEncAuth(
    walletSessionToken: string,
    sid: string,
    cborPayload: Uint8Array,
    hwSig: Uint8Array,
): Promise<EncAuthEnvelope> {
    const url = `${IDP_BASE_URL}/sessions/${encodeURIComponent(sid)}/encauth`;
    const resp = await fetch(url, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer wallet:${walletSessionToken}`,
        },
        body: JSON.stringify({
            payload: b64uEncode(cborPayload),
            hw_sig: b64uEncode(hwSig),
        }),
    });
    if (!resp.ok) {
        let detail = '';
        try {
            detail = await resp.text();
        } catch {
            // ignore
        }
        throw new Error(`upload encauth: ${resp.status} ${detail}`);
    }
    return (await resp.json()) as EncAuthEnvelope;
}

/**
 * One-shot helper: ask the IdP for (or reuse) a sid for this app,
 * build + sign an EncAuth payload anchored to that sid, then upload.
 *
 * Intended to be called from the FIDO2 sign-in / connect flow once
 * the wallet has a verified RA-TLS handshake against the enclave.
 *
 * `clientId` is the OIDC client_id of the relying party (passed in
 * the QR / sign-in payload). `sub` is the user's pairwise sub for
 * this app. The remaining fields come from the verified attestation.
 */
// ---- measurement hashing --------------------------------------------
// Moved to ./oid-digest (pure, native-dep-free, unit-testable). Re-exported
// here for back-compat with existing import sites.
export { encMeasHash, workloadDigestHash };

/** Default voucher lifetime (crypto-contract §8.3: ≤ 90 days). */
const ENCAUTH_TTL_SECONDS = 90 * 24 * 3600;

/**
 * Issue and upload the silent-rebind voucher right after a successful
 * session-relay sign-in. Call this IMMEDIATELY after the FIDO2
 * ceremony so the hardware key's biometric grace window (where the
 * platform supports one) covers the extra signature.
 *
 * Failures are the caller's to swallow: a missing voucher only means
 * the browser falls back to a wallet ceremony on the next rebind, so
 * this must never fail the sign-in itself.
 */
export async function issueEncAuthForSignIn(args: {
    /** Opaque wallet session token from the FIDO2 complete response. */
    walletSessionToken: string;
    /** Hardware key alias used for the FIDO2 ceremony (signs the voucher). */
    keyId: string;
    /** OIDC client_id of the relying party (from the QR / push payload). */
    clientId: string;
    /** Pairwise user id for this app (completeResp.userId). */
    sub: string;
    /** Enclave identity pubkey from the bootstrap response, base64url SEC1. */
    encPubB64: string;
    /** The wallet attestation digest over the verified attestation
     *  (hex, 32 bytes — `deriveQuoteHash` in connect.tsx; canonical
     *  field list in crypto-contract §4.1). The enclave's optional
     *  voucher check (`SetExpectedQuoteDigest`) compares against this
     *  same digest — never a certificate hash. */
    quoteHashHex: string;
    /** The verified attestation backing this sign-in. */
    attestation: AttestationResult;
    /** Enclave hostname this voucher is for — the browser SDK's resume selector
     *  (defaults to ''). */
    host?: string;
    /** Optional stable device identifier (defaults to ''). */
    deviceId?: string;
}): Promise<{ sid: string }> {
    const hwKey = await NativeKeys.getPublicKey(args.keyId);
    const nowSec = Math.floor(Date.now() / 1000);
    const { sid } = await signAndUploadEncAuth({
        walletSessionToken: args.walletSessionToken,
        keyId: args.keyId,
        clientId: args.clientId,
        host: args.host,
        deviceId: args.deviceId,
        payload: {
            sub: args.sub,
            workloadDigest: workloadDigestHash(args.attestation),
            encMeas: encMeasHash(args.attestation),
            encPub: b64uDecode(args.encPubB64),
            quoteHash: hexToBytes(args.quoteHashHex),
            notBefore: nowSec - 60, // tolerate modest clock skew
            notAfter: nowSec + ENCAUTH_TTL_SECONDS,
            hwPub: b64uDecode(hwKey.publicKey),
        },
    });
    return { sid };
}

export async function signAndUploadEncAuth(args: {
    walletSessionToken: string;
    keyId: string;
    clientId: string;
    deviceId?: string;
    /** Enclave hostname this voucher is for — the browser SDK's resume selector. */
    host?: string;
    payload: Omit<EncAuthPayload, 'sid'>;
}): Promise<{ sid: string; envelope: EncAuthEnvelope }> {
    // Step 1: allocate (or reuse) a sid for (user, client_id, device).
    const allocUrl = `${IDP_BASE_URL}/sessions/encauth`;
    const allocResp = await fetch(allocUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer wallet:${args.walletSessionToken}`,
        },
        body: JSON.stringify({ client_id: args.clientId, device_id: args.deviceId ?? '' }),
    });
    if (!allocResp.ok) {
        const detail = await allocResp.text().catch(() => '');
        throw new Error(`allocate encauth sid: ${allocResp.status} ${detail}`);
    }
    const allocBody = (await allocResp.json()) as { sid: string };
    const sid = allocBody.sid;
    if (!sid) throw new Error('allocate encauth sid: server returned no sid');

    // Step 2: sign with the allocated sid embedded.
    const fullPayload: EncAuthPayload = { ...args.payload, sid };
    const { payload: cborBytes, hwSig } = await signEncAuth(args.keyId, fullPayload);

    // Step 3: upload payload + hw_sig in the same POST shape.
    const putResp = await fetch(allocUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer wallet:${args.walletSessionToken}`,
        },
        body: JSON.stringify({
            client_id: args.clientId,
            device_id: args.deviceId ?? '',
            payload: b64uEncode(cborBytes),
            hw_sig: b64uEncode(hwSig),
            // Unsigned selection hint: the browser SDK can't compute the
            // workload digest, so it resumes vouchers by host. The enclave
            // re-verifies the workload digest at consumption, so this hint
            // can't be used to smuggle a wrong voucher.
            host: args.host ?? '',
        }),
    });
    if (!putResp.ok) {
        const detail = await putResp.text().catch(() => '');
        throw new Error(`upload encauth: ${putResp.status} ${detail}`);
    }
    const putBody = (await putResp.json()) as { sid: string; envelope: EncAuthEnvelope };
    return { sid: putBody.sid, envelope: putBody.envelope };
}
