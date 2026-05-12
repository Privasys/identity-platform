// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Generate a cryptographically random session ID (hex-encoded, 32 bytes).
 */
export function generateSessionId(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Deep-link host used for universal links (iOS applinks / Android intent). */
const DEEPLINK_HOST = 'privasys.id';

/** Default relay host (used when one cannot be derived from `brokerUrl`). */
const DEFAULT_RELAY_HOST = 'relay.privasys.org';

/**
 * Wire version of the descriptor JSON the wallet fetches from the relay.
 *
 * The QR code carries only `{ v, s, h, r }` — a session id, a 16-byte
 * SHA-256 prefix of the descriptor, and the relay host. The wallet GETs
 * the descriptor from `https://<r>/connect/<s>` and verifies the hash
 * before trusting any of the fields below. This keeps the QR scannable
 * (~150 chars) regardless of how many policy fields we add over time.
 *
 * Bumping `v` requires a wallet capable of understanding the new shape;
 * old wallets must reject unknown versions.
 */
export const DESCRIPTOR_VERSION = 1;

/**
 * Descriptor describing a single sign-in session. Published by the SDK to
 * the relay's `/connect/{sessionId}` endpoint and fetched by the wallet
 * after scanning the QR.
 */
export interface QRDescriptor {
    /** Descriptor format version. Wallets MUST reject unknown versions. */
    v: number;
    origin: string;
    sessionId: string;
    rpId: string;
    brokerUrl: string;
    requestedAttributes?: string[];
    appName?: string;
    privacyPolicyUrl?: string;
    /**
     * When set to 'session-relay', the wallet must call
     * `<appHost>/__privasys/session-bootstrap` with `sdkPub` before the
     * FIDO2 ceremony so the IdP can bind the issued JWT to a sealed-CBOR
     * transport session.
     */
    mode?: 'session-relay' | 'standard';
    /** SDK ephemeral P-256 SEC1 uncompressed public key, base64url. */
    sdkPub?: string;
    /** Hostname (no scheme) of the enclave app to attest + bootstrap. */
    appHost?: string;
    /** Per-session replay nonce (base64url). Falls back to sessionId. */
    nonce?: string;
}

/** Backwards-compatible alias — pre-v1 callers spoke of "QRPayload". */
export type QRPayload = QRDescriptor;

function b64url(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Compute the 16-byte SHA-256 prefix used as the descriptor pin in the QR.
 * 128 bits is comfortably collision-resistant for a single-use 5-min TTL
 * descriptor with a unique sessionId — the relay would have to find a
 * second JSON body whose SHA-256 prefix collides AND publish it under the
 * same sessionId before the legitimate PUT, which is infeasible.
 */
function descriptorHash(json: string): string {
    return b64url(sha256(new TextEncoder().encode(json)).subarray(0, 16));
}

function deriveRelayHost(brokerUrl: string): string {
    try {
        return new URL(brokerUrl).host;
    } catch {
        return DEFAULT_RELAY_HOST;
    }
}

function deriveRelayBase(brokerUrl: string): string {
    try {
        const u = new URL(brokerUrl);
        const proto = u.protocol === 'wss:' ? 'https:' : u.protocol === 'ws:' ? 'http:' : u.protocol;
        return `${proto}//${u.host}`;
    } catch {
        return `https://${DEFAULT_RELAY_HOST}`;
    }
}

function buildShortLink(sessionId: string, hashB64: string, relayHost: string): string {
    const r = relayHost === DEFAULT_RELAY_HOST ? '' : `&r=${encodeURIComponent(relayHost)}`;
    return `https://${DEEPLINK_HOST}/scp?v=${DESCRIPTOR_VERSION}&s=${encodeURIComponent(sessionId)}&h=${hashB64}${r}`;
}

async function publishDescriptor(relayBase: string, sessionId: string, body: string): Promise<void> {
    const url = `${relayBase}/connect/${encodeURIComponent(sessionId)}`;
    try {
        const resp = await fetch(url, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body,
        });
        if (!resp.ok) {
            // eslint-disable-next-line no-console
            console.warn(`[privasys-auth] descriptor publish returned ${resp.status} from ${url}`);
        }
    } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('[privasys-auth] descriptor publish failed', e);
    }
}

export interface GenerateQRResult {
    sessionId: string;
    /** Short universal-link URL to encode in the QR. */
    payload: string;
    /** Resolves once the descriptor has been (attempted to be) PUT to the relay. */
    descriptorPublished: Promise<void>;
    /** 16-byte (base64url) SHA-256 prefix pinned in the QR. */
    descriptorHash: string;
}

/**
 * Build the descriptor and the corresponding short QR URL.
 *
 * The descriptor is PUT to `<relayBase>/connect/<sessionId>` in the
 * background — the wallet GETs it after scanning. If the wallet wins the
 * race against the PUT the relay returns 404 and the wallet retries
 * briefly, so callers can render the QR immediately.
 */
export function generateQRPayload(opts: {
    rpId: string;
    /** IdP hostname running /fido2/*. Defaults to `'privasys.id'`. */
    idpOrigin?: string;
    brokerUrl: string;
    sessionId?: string;
    requestedAttributes?: string[];
    appName?: string;
    privacyPolicyUrl?: string;
    mode?: 'session-relay' | 'standard';
    sdkPub?: string;
    appHost?: string;
    nonce?: string;
    /** Override for the relay base URL (defaults to `brokerUrl`'s host). */
    relayBase?: string;
}): GenerateQRResult {
    const sessionId = opts.sessionId ?? generateSessionId();
    // `origin` is the FIDO2 server (the IdP), NOT the relying-party ID.
    // Apps may set `rpId` to their own hostname while the wallet still
    // talks to `privasys.id` for the WebAuthn ceremony. Default to the
    // hosted IdP so existing app configs (which only set `rpId`) keep
    // working without changes.
    const idpOrigin = opts.idpOrigin ?? DEEPLINK_HOST;
    const desc: QRDescriptor = {
        v: DESCRIPTOR_VERSION,
        origin: idpOrigin,
        sessionId,
        rpId: opts.rpId,
        brokerUrl: opts.brokerUrl,
    };
    if (opts.requestedAttributes?.length) {
        desc.requestedAttributes = opts.requestedAttributes;
    }
    if (opts.appName) desc.appName = opts.appName;
    if (opts.privacyPolicyUrl) desc.privacyPolicyUrl = opts.privacyPolicyUrl;
    if (opts.mode === 'session-relay') {
        if (!opts.sdkPub || !opts.appHost) {
            throw new Error('generateQRPayload: session-relay mode requires sdkPub and appHost');
        }
        desc.mode = 'session-relay';
        desc.sdkPub = opts.sdkPub;
        desc.appHost = opts.appHost;
        if (opts.nonce) desc.nonce = opts.nonce;
    }

    const json = JSON.stringify(desc);
    const hashB64 = descriptorHash(json);

    const relayBase = opts.relayBase ?? deriveRelayBase(opts.brokerUrl);
    const relayHost = opts.relayBase
        ? new URL(opts.relayBase).host
        : deriveRelayHost(opts.brokerUrl);
    const payload = buildShortLink(sessionId, hashB64, relayHost);
    const descriptorPublished = publishDescriptor(relayBase, sessionId, json);

    return { sessionId, payload, descriptorPublished, descriptorHash: hashB64 };
}

/**
 * Batch QR payload for multi-app authentication.
 * Contains multiple apps — wallet authenticates all in a single flow.
 */
export interface BatchQRPayload {
    v: number;
    origin: string;
    sessionId: string;
    brokerUrl: string;
    apps: Array<{ rpId: string; sessionId: string }>;
}

/**
 * Generate a short-form batch QR (same descriptor model as the single-app
 * flow). Each app still gets its own per-relay session id.
 */
export function generateBatchQRPayload(opts: {
    brokerUrl: string;
    apps: Array<{ rpId: string; sessionId?: string }>;
    sessionId?: string;
    relayBase?: string;
}): {
    sessionId: string;
    appSessions: Array<{ rpId: string; sessionId: string }>;
    payload: string;
    descriptorPublished: Promise<void>;
    descriptorHash: string;
} {
    const sessionId = opts.sessionId ?? generateSessionId();
    const appSessions = opts.apps.map((app) => ({
        rpId: app.rpId,
        sessionId: app.sessionId ?? generateSessionId(),
    }));
    const desc: BatchQRPayload = {
        v: DESCRIPTOR_VERSION,
        origin: opts.apps[0]?.rpId ?? '',
        sessionId,
        brokerUrl: opts.brokerUrl,
        apps: appSessions,
    };

    const json = JSON.stringify(desc);
    const hashB64 = descriptorHash(json);
    const relayBase = opts.relayBase ?? deriveRelayBase(opts.brokerUrl);
    const relayHost = opts.relayBase
        ? new URL(opts.relayBase).host
        : deriveRelayHost(opts.brokerUrl);
    const payload = buildShortLink(sessionId, hashB64, relayHost);
    const descriptorPublished = publishDescriptor(relayBase, sessionId, json);

    return { sessionId, appSessions, payload, descriptorPublished, descriptorHash: hashB64 };
}
