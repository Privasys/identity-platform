// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import { sha256 } from '@noble/hashes/sha2.js';

/** Default relay host the SDK and wallet talk to in production. */
export const DEFAULT_RELAY_HOST = 'relay.privasys.org';

/** Highest descriptor version this wallet build understands. */
export const SUPPORTED_DESCRIPTOR_VERSION = 1;

function b64urlEncode(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Fetch a published descriptor from `https://<relayHost>/connect/<sessionId>`,
 * retry briefly on 404 (wallet may scan before the SDK's PUT lands), and
 * verify the body against the QR-pinned 16-byte SHA-256 prefix.
 *
 * Throws on hash mismatch, version mismatch, or after exhausting retries.
 * Returns the parsed JSON descriptor on success.
 */
export async function fetchDescriptor(
    relayHost: string,
    sessionId: string,
    expectedHashB64: string,
): Promise<any> {
    const url = `https://${relayHost}/connect/${encodeURIComponent(sessionId)}`;
    const delays = [0, 200, 400, 800];

    let lastStatus = 0;
    let body: string | null = null;
    for (let i = 0; i < delays.length; i++) {
        if (delays[i] > 0) await new Promise((r) => setTimeout(r, delays[i]));
        let resp: Response;
        try {
            resp = await fetch(url, { method: 'GET', cache: 'no-store' });
        } catch (e: any) {
            if (i === delays.length - 1) throw new Error(`descriptor fetch failed: ${e?.message ?? e}`);
            continue;
        }
        lastStatus = resp.status;
        if (resp.ok) {
            body = await resp.text();
            break;
        }
        if (resp.status !== 404) {
            throw new Error(`descriptor fetch failed: HTTP ${resp.status}`);
        }
    }
    if (body === null) {
        throw new Error(`descriptor not found after retries (last status ${lastStatus})`);
    }

    // Verify the QR pin BEFORE parsing — defends against a hostile relay
    // returning crafted JSON that exploits the parser. The pin is over
    // the exact bytes the SDK PUT, so any byte-level tampering trips it.
    const got = b64urlEncode(sha256(new TextEncoder().encode(body)).subarray(0, 16));
    if (got !== expectedHashB64) {
        throw new Error('descriptor hash mismatch (QR pin does not match relay body)');
    }

    let parsed: any;
    try {
        parsed = JSON.parse(body);
    } catch {
        throw new Error('descriptor is not valid JSON');
    }
    if (typeof parsed !== 'object' || parsed === null) {
        throw new Error('descriptor must be an object');
    }
    if (typeof parsed.v !== 'number') {
        throw new Error('descriptor missing version field');
    }
    if (parsed.v > SUPPORTED_DESCRIPTOR_VERSION) {
        throw new Error(
            `descriptor version ${parsed.v} not supported by this wallet ` +
                `(max ${SUPPORTED_DESCRIPTOR_VERSION}); please update`,
        );
    }
    return parsed;
}
