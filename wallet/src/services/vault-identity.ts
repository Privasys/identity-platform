// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What a vault approval (binding v2) is checked against before it is shown:
 * the vaults it is for, and for a policy update the policy it installs.
 *
 * - A vault's identity is what its GetVaultIdentity returned, relayed
 *   untouched: its member key, its billing id, its build (MRENCLAVE) and an
 *   SGX quote whose report data commits to the first two. `checkIdentity`
 *   checks the identity agrees with itself: member_id is the hash of the
 *   member key, and the quote carries that member id, billing id and build.
 *
 *   It does not verify the quote's signature chain, so it does not prove the
 *   identity came from a real enclave. What keeps an approval safe is each
 *   vault refusing a binding that does not name it. What this check gives is
 *   that the build shown is the build the identity claims, and that the
 *   members signed for are the ones shown.
 *
 * - `policyDigest` is PD(policy): hex SHA-256 of the policy's RFC 8785 form,
 *   under the vault's limits (ASCII member names, whole numbers within 2^53,
 *   no lone surrogates). It is what an update_policy approval binds.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlToBytes } from '@/utils/encoding';

/** A vault's identity, with the vault's own field names. */
export interface VaultIdentity {
    member_id: string;
    member_public_key: string; // hex, SEC1 uncompressed
    billing_id: string;
    mrenclave: string; // hex
    quote_b64: string; // base64url, no padding
}

const HEX = /^[0-9a-f]+$/;
// An SGX DCAP quote, version 3 or 4: a 48-byte header, then the report body,
// whose MRENCLAVE is at 64 and report data at 320.
const QUOTE_MRENCLAVE = 48 + 64;
const QUOTE_REPORT_DATA = 48 + 320;

const utf8 = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function fromHex(s: string): Uint8Array | null {
    if (s.length % 2 !== 0 || !HEX.test(s)) return null;
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
}

/** hex SHA-256 of "privasys-vault-member-v1\n" followed by the member key. */
export function memberId(memberPublicKeyHex: string): string | null {
    const pub = fromHex(memberPublicKeyHex);
    if (!pub || pub.length !== 65 || pub[0] !== 0x04) return null;
    return hex(sha256(concat(utf8('privasys-vault-member-v1\n'), pub)));
}

/**
 * Whether the identity agrees with itself. Returns the build it claims (its
 * MRENCLAVE, lowercase hex), or null.
 */
export function checkIdentity(id: VaultIdentity): string | null {
    if (!id || typeof id.member_id !== 'string' || typeof id.billing_id !== 'string') return null;
    if (memberId(String(id.member_public_key)) !== id.member_id) return null;
    if (id.billing_id === '' || /[\n\r]/.test(id.billing_id)) return null;
    let quote: Uint8Array;
    try {
        quote = base64urlToBytes(String(id.quote_b64));
    } catch {
        return null;
    }
    if (quote.length < QUOTE_REPORT_DATA + 64) return null;
    const version = quote[0] | (quote[1] << 8);
    const tee = quote[4] | (quote[5] << 8) | (quote[6] << 16) | (quote[7] << 24);
    if ((version !== 3 && version !== 4) || tee !== 0) return null;
    const want = sha256(utf8(`privasys-vault-identity-v1\n${id.member_id}\n${id.billing_id}`));
    for (let i = 0; i < 32; i++) if (quote[QUOTE_REPORT_DATA + i] !== want[i]) return null;
    const mrenclave = hex(quote.slice(QUOTE_MRENCLAVE, QUOTE_MRENCLAVE + 32));
    if (String(id.mrenclave).toLowerCase() !== mrenclave) return null;
    return mrenclave;
}

/** The members an approval names, checked against the identities relayed with it. */
export interface CheckedMembers {
    /** The member ids, sorted. */
    members: string[];
    /** The builds those members claim, distinct, lowercase hex. */
    builds: string[];
    /** Their billing ids, distinct. */
    billingIds: string[];
}

/**
 * Every member named must have an identity that agrees with itself. Null
 * otherwise: the approval is then not shown as approvable.
 */
export function checkMembers(members: string[], identities: VaultIdentity[] | undefined): CheckedMembers | null {
    if (!Array.isArray(members) || members.length === 0 || !Array.isArray(identities)) return null;
    const byId = new Map<string, { build: string; billing: string }>();
    for (const id of identities) {
        const build = checkIdentity(id);
        if (!build) return null;
        byId.set(id.member_id, { build, billing: id.billing_id });
    }
    const builds = new Set<string>();
    const billing = new Set<string>();
    for (const m of members) {
        const got = byId.get(m);
        if (!got) return null;
        builds.add(got.build);
        billing.add(got.billing);
    }
    if (new Set(members).size !== members.length) return null;
    return { members: [...members].sort(), builds: [...builds].sort(), billingIds: [...billing].sort() };
}

// ── Policy digest ──────────────────────────────────────────────────────────

const ASCII = /^[\x00-\x7f]*$/;

function wellFormed(s: string): boolean {
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c === 0xfffd) return false;
        if (c >= 0xd800 && c <= 0xdbff) {
            const d = s.charCodeAt(i + 1);
            if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
            i++;
        } else if (c >= 0xdc00 && c <= 0xdfff) {
            return false;
        }
    }
    return true;
}

function canonical(v: unknown): string {
    if (v === null) return 'null';
    if (v === true) return 'true';
    if (v === false) return 'false';
    if (typeof v === 'number') {
        if (!Number.isSafeInteger(v)) throw new Error('policy: a number is not a whole number within 2^53');
        return String(v);
    }
    if (typeof v === 'string') {
        if (!wellFormed(v)) throw new Error('policy: a string holds U+FFFD or a lone surrogate');
        return JSON.stringify(v);
    }
    if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
    if (typeof v === 'object') {
        const keys = Object.keys(v as object);
        for (const k of keys) if (!ASCII.test(k)) throw new Error('policy: a member name is not ASCII');
        // ASCII names: code unit order is byte order.
        keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
        return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}`;
    }
    throw new Error('policy: not JSON');
}

/** The policy's RFC 8785 form. Throws on what the vault would refuse. */
export function canonicalPolicy(policy: unknown): string {
    if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('policy: not an object');
    return canonical(policy);
}

/** PD(policy): hex SHA-256 of its canonical form. */
export function policyDigest(policy: unknown): string {
    return hex(sha256(utf8(canonicalPolicy(policy))));
}
