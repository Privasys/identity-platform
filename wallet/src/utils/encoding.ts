// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Shared encoding helpers. base64url (RFC 4648 §5, no padding) and a canonical
 * JSON serialiser, consolidated here so the wallet ships one implementation
 * instead of a near-identical copy in every service.
 */

/** Encode bytes as base64url (no padding). */
export function bytesToBase64url(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] ?? 0);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode a base64url string (padding optional) to bytes. */
export function base64urlToBytes(s: string): Uint8Array {
    const std = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
    const bin = atob(std);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/**
 * Canonical JSON: keys sorted, compact separators, no whitespace. Matches the
 * verifier's `crypto.canonical_json` so JS and Python serialise identically for
 * ASCII string + integer values.
 */
export function canonicalJson(obj: Record<string, string | number>): string {
    const keys = Object.keys(obj).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + JSON.stringify(obj[k])).join(',') + '}';
}
