// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

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

/**
 * QR payload that the wallet scans to begin authentication.
 */
export interface QRPayload {
    origin: string;
    sessionId: string;
    rpId: string;
    brokerUrl: string;
}

/**
 * Encode a JSON QR payload as a universal-link URL.
 *
 * When a regular phone camera scans the QR, it opens the URL:
 *   - If the Privasys Wallet is installed, iOS/Android routes it to the app
 *     via the registered `applinks:privasys.id` associated domain.
 *   - Otherwise the browser opens `https://privasys.id/scp` which can show
 *     install instructions.
 *
 * The wallet's QR scanner handles both formats (URL and raw JSON).
 */
function wrapAsUniversalLink(json: string): string {
    // Base64url-encode the JSON (no padding) so it's URL-safe
    const b64 = btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `https://${DEEPLINK_HOST}/scp?p=${b64}`;
}

/**
 * Generate the JSON payload to encode in a QR code.
 * The wallet scans this and connects to the broker to pair with the browser.
 *
 * The returned `payload` is a universal-link URL that wraps the JSON,
 * so both the wallet's QR scanner and a regular phone camera work.
 */
export function generateQRPayload(opts: {
    rpId: string;
    brokerUrl: string;
    sessionId?: string;
}): { sessionId: string; payload: string } {
    const sessionId = opts.sessionId ?? generateSessionId();
    const qr: QRPayload = {
        origin: opts.rpId,
        sessionId,
        rpId: opts.rpId,
        brokerUrl: opts.brokerUrl,
    };
    return { sessionId, payload: wrapAsUniversalLink(JSON.stringify(qr)) };
}

/**
 * Batch QR payload for multi-app authentication.
 * Contains multiple apps — wallet authenticates all in a single flow.
 */
export interface BatchQRPayload {
    origin: string;
    sessionId: string;
    brokerUrl: string;
    apps: Array<{ rpId: string; sessionId: string }>;
}

/**
 * Generate a QR payload for batch (multi-app) authentication.
 * Each app gets its own session ID for its broker relay.
 */
export function generateBatchQRPayload(opts: {
    brokerUrl: string;
    apps: Array<{ rpId: string; sessionId?: string }>;
    sessionId?: string;
}): { sessionId: string; appSessions: Array<{ rpId: string; sessionId: string }>; payload: string } {
    const sessionId = opts.sessionId ?? generateSessionId();
    const appSessions = opts.apps.map((app) => ({
        rpId: app.rpId,
        sessionId: app.sessionId ?? generateSessionId(),
    }));
    const qr: BatchQRPayload = {
        origin: opts.apps[0]?.rpId ?? '',
        sessionId,
        brokerUrl: opts.brokerUrl,
        apps: appSessions,
    };
    return { sessionId, appSessions, payload: wrapAsUniversalLink(JSON.stringify(qr)) };
}
