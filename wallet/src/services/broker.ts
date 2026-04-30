// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Auth broker WebSocket client.
 *
 * Connects to the auth broker relay to exchange session tokens with
 * the browser. The broker is a stateless relay — messages are forwarded
 * verbatim between paired WebSocket connections sharing a session ID.
 */

export interface BrokerMessage {
    type: string;
    payload?: Record<string, unknown>;
}

export interface BrokerConnection {
    send: (msg: BrokerMessage) => void;
    close: () => void;
}

/**
 * Connect to the auth broker and relay a session token to the browser.
 *
 * @param brokerUrl  WebSocket URL for the relay (e.g. wss://auth.privasys.org/relay).
 * @param sessionId  Session ID shared with the browser (from QR or push).
 * @param sessionToken  The opaque session token from the enclave's FIDO2 endpoint.
 * @param pushToken  Expo push token for future auth requests.
 * @param attributes  Optional profile attributes resolved from the wallet's local store.
 * @param sessionRelay  Optional sealed-transport binding {sessionId, encPub, expiresAt}
 *                      from `/__privasys/session-bootstrap`. When set, the SDK
 *                      iframe completes the ECDH handshake and instantiates a
 *                      `PrivasysSession` for sealed CBOR-AES-GCM requests.
 */
export function relaySessionToken(
    brokerUrl: string,
    sessionId: string,
    sessionToken: string,
    pushToken: string | null,
    attributes?: Record<string, string>,
    sessionRelay?: { sessionId: string; encPub: string; expiresAt?: number },
): Promise<void> {
    return new Promise((resolve, reject) => {
        let settled = false;

        const timeout = setTimeout(() => {
            if (!settled) {
                settled = true;
                reject(new Error('Broker relay timed out'));
            }
            ws.close();
        }, 15_000);

        const wsUrl = `${brokerUrl}?session=${encodeURIComponent(sessionId)}&role=wallet`;
        const ws = new WebSocket(wsUrl);

        const sendResult = () => {
            if (settled) return;
            const msg: Record<string, unknown> = {
                type: 'auth-result',
                sessionToken,
                pushToken,
            };
            if (attributes) {
                msg.attributes = attributes;
            }
            if (sessionRelay) {
                msg.sessionRelay = sessionRelay;
            }
            ws.send(JSON.stringify(msg));
            settled = true;
            clearTimeout(timeout);
            ws.close();
            resolve();
        };

        ws.onopen = () => {
            // Send immediately — in the normal QR flow the browser is
            // already connected, and the hub will forward the message.
            // The hub only notifies the *other* peer on join, so the
            // wallet never receives a trigger in the browser-first case.
            sendResult();
        };

        ws.onmessage = (event) => {
            try {
                const data: BrokerMessage =
                    typeof event.data === 'string' ? JSON.parse(event.data) : {};

                if (data.type === 'browser-waiting') {
                    // Wallet connected first (push flow) and browser just
                    // arrived — send the token now.
                    sendResult();
                }
            } catch {
                // Ignore non-JSON messages
            }
        };

        ws.onerror = () => {
            clearTimeout(timeout);
            if (!settled) {
                settled = true;
                reject(new Error('Broker WebSocket error'));
            }
        };

        ws.onclose = () => {
            clearTimeout(timeout);
            if (!settled) {
                settled = true;
                // Resolve on clean close (broker may close after relay)
                resolve();
            }
        };
    });
}

/**
 * Connect to broker and listen for auth requests (push-initiated flow).
 *
 * @param brokerUrl  WebSocket URL for the relay.
 * @param sessionId  Session ID from the push notification.
 * @param onRequest  Callback when the browser sends an auth request.
 * @returns A connection handle to send responses and close.
 */
export function listenForAuthRequest(
    brokerUrl: string,
    sessionId: string,
    onRequest: (msg: BrokerMessage) => void
): BrokerConnection {
    const wsUrl = `${brokerUrl}?session=${encodeURIComponent(sessionId)}&role=wallet`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        ws.send(
            JSON.stringify({
                type: 'wallet-hello',
                payload: { version: '0.2.0' }
            })
        );
    };

    ws.onmessage = (event) => {
        try {
            const data: BrokerMessage =
                typeof event.data === 'string' ? JSON.parse(event.data) : {};
            onRequest(data);
        } catch {
            // Ignore
        }
    };

    return {
        send: (msg) => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(msg));
            }
        },
        close: () => ws.close()
    };
}
