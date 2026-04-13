// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import type { AuthConfig, AuthEvents, AuthResult, AuthState, AttestationInfo, BatchAppConfig, BatchAuthResult } from './types';
import { generateQRPayload, generateBatchQRPayload } from './qr';
import { SessionManager } from './session';

const DEFAULT_TIMEOUT = 120_000;

/**
 * Main client for Privasys Wallet authentication from a browser.
 *
 * Usage:
 * ```ts
 * const auth = new PrivasysAuth({
 *   rpId: 'myapp.apps.privasys.org',
 *   brokerUrl: 'wss://broker.privasys.org',
 * });
 *
 * const { sessionId, payload } = auth.createQR();
 * // render `payload` as a QR code
 *
 * const result = await auth.waitForResult(sessionId);
 * ```
 */
export class PrivasysAuth {
    readonly config: AuthConfig;
    readonly sessions: SessionManager;
    private events: AuthEvents;
    private activeConnections = new Map<string, WebSocket>();

    constructor(config: AuthConfig, events: AuthEvents = {}) {
        this.config = {
            attestation: 'required',
            timeout: DEFAULT_TIMEOUT,
            ...config,
        };
        this.events = events;
        this.sessions = new SessionManager();
    }

    /**
     * Generate a QR payload for the wallet to scan.
     * Returns the sessionId and the JSON payload string to encode in the QR.
     */
    createQR(sessionId?: string): { sessionId: string; payload: string } {
        return generateQRPayload({
            rpId: this.config.rpId,
            brokerUrl: this.config.brokerUrl,
            sessionId,
        });
    }

    /**
     * Connect to the broker and wait for the wallet to authenticate.
     * Resolves with the auth result or rejects on timeout/error.
     */
    waitForResult(sessionId: string): Promise<AuthResult> {
        return new Promise<AuthResult>((resolve, reject) => {
            const timeout = this.config.timeout ?? DEFAULT_TIMEOUT;

            // Build WebSocket URL
            const url = new URL(this.config.brokerUrl);
            url.searchParams.set('session', sessionId);
            url.searchParams.set('role', 'browser');
            const ws = new WebSocket(url.toString());

            this.activeConnections.set(sessionId, ws);
            this.setState('waiting-for-scan');

            const timer = setTimeout(() => {
                this.setState('timeout');
                this.cleanup(sessionId);
                reject(new Error('Authentication timed out'));
            }, timeout);

            ws.onopen = () => {
                // Connected to broker, waiting for wallet peer
                this.setState('waiting-for-scan');
            };

            ws.onmessage = (event: MessageEvent) => {
                try {
                    const msg = JSON.parse(typeof event.data === 'string' ? event.data : '{}');
                    this.handleMessage(sessionId, msg, resolve, timer);
                } catch (err) {
                    // Ignore malformed messages
                }
            };

            ws.onerror = () => {
                clearTimeout(timer);
                this.setState('error');
                this.cleanup(sessionId);
                reject(new Error('WebSocket connection failed'));
            };

            ws.onclose = (event: CloseEvent) => {
                clearTimeout(timer);
                this.cleanup(sessionId);
                // Normal close after successful auth is fine
                if (event.code !== 1000) {
                    this.setState('error');
                    reject(new Error(`Connection closed (code ${event.code})`));
                }
            };
        });
    }

    /**
     * For returning users: send a push notification via the broker
     * to the wallet, then wait for them to approve.
     */
    async notifyAndWait(pushToken: string, sessionId?: string): Promise<AuthResult> {
        const sid = sessionId ?? this.createQR().sessionId;

        // POST to broker /notify endpoint
        const brokerBase = this.config.brokerUrl
            .replace('wss://', 'https://')
            .replace('ws://', 'http://')
            .replace(/\/relay\/?$/, '');

        const resp = await fetch(`${brokerBase}/notify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                pushToken,
                sessionId: sid,
                rpId: this.config.rpId,
                origin: this.config.rpId,
                brokerUrl: this.config.brokerUrl,
            }),
        });

        if (!resp.ok) {
            const body = await resp.text();
            throw new Error(`Push notification failed: ${body}`);
        }

        return this.waitForResult(sid);
    }

    /** Cancel an in-progress authentication. */
    cancel(sessionId: string): void {
        this.cleanup(sessionId);
        this.setState('idle');
    }

    /** Cancel all active connections. */
    destroy(): void {
        for (const id of this.activeConnections.keys()) {
            this.cleanup(id);
        }
        this.setState('idle');
    }

    /**
     * Batch auth: authenticate with multiple enclaves in a single wallet approval.
     * Returns a QR payload and a promise that resolves when all (or some) apps are authenticated.
     */
    getMultiple(apps: BatchAppConfig[]): {
        sessionId: string;
        appSessions: Array<{ rpId: string; sessionId: string }>;
        payload: string;
        result: Promise<BatchAuthResult>;
    } {
        const { sessionId, appSessions, payload } = generateBatchQRPayload({
            brokerUrl: this.config.brokerUrl,
            apps: apps.map((a) => ({ rpId: a.rpId })),
        });

        // Open one WebSocket per app, wait for all to complete or timeout
        const result = this.waitForBatch(appSessions);

        return { sessionId, appSessions, payload, result };
    }

    /** Update the event handlers. */
    on(events: Partial<AuthEvents>): void {
        this.events = { ...this.events, ...events };
    }

    // ---- internals ----

    private handleMessage(
        sessionId: string,
        msg: Record<string, unknown>,
        resolve: (result: AuthResult) => void,
        timer: ReturnType<typeof setTimeout>,
    ): void {
        switch (msg.type) {
            case 'peer-joined':
            case 'wallet-waiting':
                this.setState('wallet-connected');
                break;

            case 'auth-result': {
                clearTimeout(timer);
                this.setState('complete');

                const result: AuthResult = {
                    sessionToken: msg.sessionToken as string,
                    sessionId,
                    attestation: msg.attestation as AttestationInfo | undefined,
                    pushToken: (msg.pushToken as string | undefined) || undefined,
                };

                // Store session locally
                this.sessions.store({
                    token: result.sessionToken,
                    rpId: this.config.rpId,
                    origin: globalThis.location?.origin ?? '',
                    authenticatedAt: Date.now(),
                    pushToken: result.pushToken,
                    brokerUrl: this.config.brokerUrl,
                });

                this.events.onAuthenticated?.(result);
                this.cleanup(sessionId);
                resolve(result);
                break;
            }

            case 'auth-error': {
                clearTimeout(timer);
                this.setState('error');
                this.cleanup(sessionId);
                const err = new Error((msg.message as string) ?? 'Authentication failed');
                this.events.onError?.(err);
                break;
            }

            case 'authenticating':
                this.setState('authenticating');
                break;
        }
    }

    private setState(state: AuthState): void {
        this.events.onStateChange?.(state);
    }

    private async waitForBatch(
        appSessions: Array<{ rpId: string; sessionId: string }>,
    ): Promise<BatchAuthResult> {
        const timeout = this.config.timeout ?? DEFAULT_TIMEOUT;
        this.setState('waiting-for-scan');

        const settled = await Promise.allSettled(
            appSessions.map((app) =>
                Promise.race([
                    this.waitForResult(app.sessionId),
                    new Promise<never>((_, reject) =>
                        setTimeout(() => reject(new Error('Batch item timed out')), timeout),
                    ),
                ]),
            ),
        );

        const results: AuthResult[] = [];
        const errors: Array<{ rpId: string; error: string }> = [];

        for (let i = 0; i < settled.length; i++) {
            const outcome = settled[i];
            if (outcome.status === 'fulfilled') {
                results.push(outcome.value);
            } else {
                errors.push({
                    rpId: appSessions[i].rpId,
                    error: outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason),
                });
            }
        }

        this.setState(errors.length === 0 ? 'complete' : 'error');
        return { results, errors };
    }

    private cleanup(sessionId: string): void {
        const ws = this.activeConnections.get(sessionId);
        if (ws) {
            if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
                ws.close(1000);
            }
            this.activeConnections.delete(sessionId);
        }
    }
}
