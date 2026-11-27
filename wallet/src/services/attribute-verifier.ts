// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The Privasys Attribute Verifier: the confidential app that turns raw evidence
 * for an attribute (a provider's signed ID token, a mail code, a card check)
 * into a signed proof, and re-attests it on demand. The counterpart of the
 * Identity Verifier (services/kyc), and reached the same way: resolved by name
 * from the platform, attested over RA-TLS with its image digest pinned, then
 * called over that attested channel.
 *
 * Every call is signed twice, over the same canonical message:
 *  - by the holder's key for this verifier (services/holder-keys), the same on
 *    every device, which proves the evidence is this holder's;
 *  - by the device's hardware key, which binds the proof to this device and
 *    is the key the wallet's attestation (WIA) names.
 * Signatures are raw r||s ES256 over SHA-256 of the message bytes.
 *
 * The verifier keeps nothing about people; the wallet keeps the raw material
 * and the proofs (stores/profile).
 */

import { p256 } from '@noble/curves/nist.js';
import * as Crypto from 'expo-crypto';
import { sha256 } from '@noble/hashes/sha2.js';

import { getAttestationServerToken } from '@/services/app-attest';
import { attestEnclave, inspectAttestation } from '@/services/attestation';
import { derToRawEcdsa } from '@/services/encauth';
import { deriveHolderKey, holderCommitment } from '@/services/holder-keys';
import { ensureWia } from '@/services/wia';
import { useProfileStore } from '@/stores/profile';
import { useSettingsStore } from '@/stores/settings';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';

import * as NativeKeys from '../../modules/native-keys/src/index';
import * as NativeRaTls from '../../modules/native-ratls/src/index';

/** The platform the verifier is resolved from. The verifier runs on dev first,
 *  so preview and development builds point here at the test platform. */
const PLATFORM_API_BASE =
    process.env.EXPO_PUBLIC_ATTRIBUTE_VERIFIER_PLATFORM_URL ??
    process.env.EXPO_PUBLIC_PLATFORM_API_URL ??
    'https://api.developer.privasys.org';
const APP_NAME = process.env.EXPO_PUBLIC_ATTRIBUTE_VERIFIER_APP ?? 'privasys-attribute-verifier';
/** The attested image digest (org.privasys, 1.3.6.1.4.1.65230.4.2). */
const IMAGE_OID = '1.3.6.1.4.1.65230.4.2';
const ATTESTATION_SERVER = 'https://as.privasys.org';
/** The device's hardware key: the one the WIA names. */
const DEVICE_KEY_ID = 'privasys-wallet-default';

export type AttestKind = 'oidc_id_token' | 'github' | 'mail_code' | 'card_check' | 'proof';

/** One signed proof, as the verifier returns it. */
export interface AttributeProof {
    attr: string;
    value: unknown;
    method: 'proven' | 'observed';
    /** Who vouches: google, microsoft, linkedin, oidc:<issuer>, github, privasys_mail, card_bank. */
    source: string;
    /** Display data; the wallet composes the sentence (attributeSourceLabel). */
    label: Record<string, string | null> | null;
    /** The JWS the verifier signed. */
    proof: string;
}

export class AttributeVerifierError extends Error {
    constructor(
        readonly status: number,
        message: string,
        readonly body: Record<string, unknown> | null = null,
    ) {
        super(message);
    }
}

// ---------------------------------------------------------------- canonical JSON

/**
 * Canonical JSON exactly as the verifier writes it (Go's encoding/json with
 * HTML escaping off, keys sorted, no whitespace): what both keys sign must be
 * byte for byte what the verifier recomputes. Go differs from JSON.stringify
 * in its string escapes: control characters other than \b \f \n \r \t become
 * \u00xx, and U+2028 and U+2029 are always escaped. Pinned against the
 * verifier's own output in __tests__/attribute-verifier.test.ts.
 */
export function canonicalJson(v: unknown): string {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'string') return goString(v);
    if (typeof v === 'number') {
        if (!Number.isFinite(v)) throw new Error('canonicalJson: not a finite number');
        return JSON.stringify(v);
    }
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
    if (typeof v === 'object') {
        const o = v as Record<string, unknown>;
        const keys = Object.keys(o)
            .filter((k) => o[k] !== undefined)
            .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
        return '{' + keys.map((k) => goString(k) + ':' + canonicalJson(o[k])).join(',') + '}';
    }
    throw new Error(`canonicalJson: cannot encode a ${typeof v}`);
}

function goString(s: string): string {
    let out = '"';
    for (const ch of s) {
        const c = ch.codePointAt(0)!;
        if (ch === '"') out += '\\"';
        else if (ch === '\\') out += '\\\\';
        else if (ch === '\n') out += '\\n';
        else if (ch === '\r') out += '\\r';
        else if (ch === '\t') out += '\\t';
        else if (ch === '\b') out += '\\b';
        else if (ch === '\f') out += '\\f';
        else if (c < 0x20 || c === 0x2028 || c === 0x2029) out += '\\u' + c.toString(16).padStart(4, '0');
        else out += ch;
    }
    return out + '"';
}

const utf8 = (s: string) => new TextEncoder().encode(s);

/** b64u(SHA-256(canonical(material))): what the attest message names. */
export function materialDigest(material: unknown): string {
    return bytesToBase64url(sha256(utf8(canonicalJson(material))));
}

/** The message both keys sign for an attest. */
export function attestMessage(kind: AttestKind, material: unknown, challenge: string): Uint8Array {
    return utf8(canonicalJson({ op: 'attest', kind, material: materialDigest(material), challenge }));
}

/** The message both keys sign to start a mail code. */
function mailStartMessage(email: string, challenge: string): Uint8Array {
    return utf8(canonicalJson({ op: 'mail_start', email, challenge }));
}

/** The message the device key alone signs for a disclosure. */
export function discloseMessage(proofJti: string, rpId: string, sub: string, nonce: string, ts: number): Uint8Array {
    return utf8(canonicalJson({ op: 'disclose', proof: proofJti, rp_id: rpId, sub, nonce, ts }));
}

// ---------------------------------------------------------------- keys

function seed(): string {
    const s = useProfileStore.getState().profile?.pairwiseSeed;
    if (!s) throw new Error('attribute verifier: this wallet is not set up');
    return s;
}

/** A fresh 16-byte salt, and the commitment a third party sees for it. */
export function newCommitment(): { salt: string; commitment: string } {
    const salt = new Uint8Array(Crypto.getRandomBytes(16));
    const { publicKey } = deriveHolderKey(seed(), 'attribute');
    return { salt: bytesToBase64url(salt), commitment: holderCommitment(publicKey, salt) };
}

function holderBlock(msg: Uint8Array, saltB64: string): { hk_pub: string; salt: string; sig: string } {
    const { secretKey, publicKey } = deriveHolderKey(seed(), 'attribute');
    // noble hashes the message with SHA-256 first, and returns r||s.
    const sig = p256.sign(msg, secretKey);
    return { hk_pub: bytesToBase64url(publicKey), salt: saltB64, sig: bytesToBase64url(sig) };
}

async function deviceBlock(msg: Uint8Array): Promise<{ pub: string; sig: string }> {
    const info = await NativeKeys.getPublicKey(DEVICE_KEY_ID);
    // The native key signs SHA-256 of the data and returns DER.
    const der = (await NativeKeys.sign(DEVICE_KEY_ID, bytesToBase64url(msg))).signature;
    return { pub: info.publicKey, sig: bytesToBase64url(derToRawEcdsa(base64urlToBytes(der))) };
}

// ---------------------------------------------------------------- the channel

interface Resolved {
    host: string;
    port: number;
    imageDigest: string;
}
let resolved: Resolved | null = null;
let attestedAt = 0;
/** Re-attest the enclave at most this often within one session. */
const ATTEST_TTL_MS = 10 * 60 * 1000;

async function resolve(): Promise<Resolved> {
    if (resolved) return resolved;
    const res = await fetch(`${PLATFORM_API_BASE}/api/v1/apps/by-name/${encodeURIComponent(APP_NAME)}/resolve`);
    if (!res.ok) throw new AttributeVerifierError(res.status, 'the attribute verifier could not be found');
    const j = (await res.json()) as { hostname?: string; image_digest?: string };
    if (!j.hostname || !j.image_digest) throw new AttributeVerifierError(502, 'the attribute verifier is not published yet');
    const [host, port] = j.hostname.split(':');
    resolved = { host, port: port ? Number(port) : 443, imageDigest: j.image_digest.toLowerCase() };
    return resolved;
}

/**
 * Prove the verifier is the published build before sending it anything: its
 * image digest must match what the platform publishes, and the attestation
 * service must verify the enclave. Refuses otherwise.
 */
async function channel(): Promise<Resolved> {
    if (resolved && Date.now() - attestedAt < ATTEST_TTL_MS) return resolved;
    // What the platform publishes is read afresh with each attestation: the
    // verifier is upgraded under a running wallet, and the build it publishes
    // then is the one to hold the enclave to.
    resolved = null;
    let v = await resolve();
    const origin = (r: Resolved) => (r.port === 443 ? r.host : `${r.host}:${r.port}`);
    let inspected = await inspectAttestation(origin(v));
    let digest = inspected.custom_oids?.find((o) => o.oid === IMAGE_OID)?.value_hex.toLowerCase();
    if (digest !== v.imageDigest) {
        // An upgrade can land between the two reads: read once more, and
        // refuse only if the enclave still is not the published build.
        resolved = null;
        v = await resolve();
        inspected = await inspectAttestation(origin(v));
        digest = inspected.custom_oids?.find((o) => o.oid === IMAGE_OID)?.value_hex.toLowerCase();
        if (digest !== v.imageDigest) {
            resolved = null;
            throw new AttributeVerifierError(0, 'the attribute verifier is not the published build; nothing was sent');
        }
    }
    const outcome = await attestEnclave(origin(v), {
        tee: inspected.tee_type ?? 'tdx',
        mode: useSettingsStore.getState().verificationMode,
        attestationServer: ATTESTATION_SERVER,
        attestationServerToken: await getAttestationServerToken(),
    });
    if (outcome.status !== 'verified') {
        throw new AttributeVerifierError(0, `the attribute verifier could not prove itself (${outcome.status})`);
    }
    attestedAt = Date.now();
    return v;
}

async function post<T>(path: string, body: unknown): Promise<T> {
    const v = await channel();
    const res = await NativeRaTls.post(v.host, v.port, path, JSON.stringify(body), {});
    let parsed: Record<string, unknown> | null = null;
    try {
        parsed = JSON.parse(res.body);
    } catch {
        parsed = null;
    }
    if (res.status < 200 || res.status >= 300) {
        throw new AttributeVerifierError(res.status, String(parsed?.error ?? `HTTP ${res.status}`), parsed);
    }
    return parsed as T;
}

async function challenge(): Promise<string> {
    return (await post<{ challenge: string }>('/challenge', {})).challenge;
}

async function wia(): Promise<string> {
    return (await ensureWia().catch(() => null)) ?? '';
}

// ---------------------------------------------------------------- calls

/**
 * Turn raw material into proofs bound to this device. `salt` is the one whose
 * commitment went into the material (the provider nonce, the card check), or
 * a fresh one for a mail code or a rebind.
 */
export async function attest(kind: AttestKind, material: Record<string, unknown>, salt: string): Promise<AttributeProof[]> {
    const ch = await challenge();
    const msg = attestMessage(kind, material, ch);
    const body = {
        kind,
        material,
        holder: holderBlock(msg, salt),
        device: await deviceBlock(msg),
        wia: await wia(),
        challenge: ch,
    };
    return (await post<{ proofs: AttributeProof[] }>('/attest', body)).proofs ?? [];
}

/** Ask the verifier to mail a code to `email`. Returns the token to send back with the code. */
export async function startMailCode(
    email: string,
    salt: string,
): Promise<{ mailToken: string; expiresAt: number; codeLength: number; maxAttempts: number; resendAfter: number }> {
    const ch = await challenge();
    const msg = mailStartMessage(email, ch);
    // Signed by the holder key only: sending a code binds nothing to this
    // device, so it raises no biometric prompt. The device key signs once, at
    // redemption (attest mail_code), where the proof is bound. The verifier
    // reads the device for its rate limits from the WIA (verifier >= 0.1.3).
    const r = await post<{ mail_token: string; expires_at: number; code_length: number; max_attempts: number; resend_after: number }>(
        '/mail/start',
        { email, holder: holderBlock(msg, salt), wia: await wia(), challenge: ch },
    );
    return {
        mailToken: r.mail_token,
        expiresAt: r.expires_at,
        codeLength: r.code_length,
        maxAttempts: r.max_attempts,
        resendAfter: r.resend_after,
    };
}

/** The `jti` of a proof JWS, read from its payload. */
function proofJti(proof: string): string {
    const payload = JSON.parse(new TextDecoder().decode(base64urlToBytes(proof.split('.')[1] ?? '')));
    if (typeof payload?.jti !== 'string') throw new Error('attribute verifier: a proof without a jti');
    return payload.jti;
}

/**
 * A fresh, audience-bound disclosure of a proof for one relying party, signed
 * by the device key alone. privasys.id relays it inside the sign-in.
 */
export async function disclose(proof: string, rpId: string, sub: string, nonce: string): Promise<string> {
    const ts = Math.floor(Date.now() / 1000);
    const msg = discloseMessage(proofJti(proof), rpId, sub, nonce, ts);
    const r = await post<{ token: string }>('/disclose', {
        proof,
        rp_id: rpId,
        sub,
        nonce,
        ts,
        device: await deviceBlock(msg),
        wia: await wia(),
    });
    return r.token;
}

/** Forget the resolved verifier (a new build published, a failed attestation). */
export function resetAttributeVerifier(): void {
    resolved = null;
    attestedAt = 0;
}
