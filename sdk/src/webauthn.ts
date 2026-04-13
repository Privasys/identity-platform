// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

import type { AuthResult } from './types';
import { SessionManager } from './session';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64urlEncode(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str: string): ArrayBuffer {
    let padded = str.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4 !== 0) padded += '=';
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function randomHex(bytes: number): string {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Configuration for the WebAuthn client. */
export interface WebAuthnConfig {
    /** Management service API base URL (e.g., "https://api.developer.privasys.org"). */
    apiBase: string;
    /** App name or UUID as registered in the platform. */
    appName: string;
    /** Timeout for the WebAuthn ceremony in milliseconds (default: 60000). */
    timeout?: number;
}

/** State of a WebAuthn operation. */
export type WebAuthnState =
    | 'idle'
    | 'requesting-options'
    | 'ceremony'
    | 'verifying'
    | 'complete'
    | 'error';

/** Events emitted during WebAuthn operations. */
export interface WebAuthnEvents {
    onStateChange?: (state: WebAuthnState) => void;
    onAuthenticated?: (result: AuthResult) => void;
    onError?: (error: Error) => void;
}

// ---------------------------------------------------------------------------
// WebAuthnClient
// ---------------------------------------------------------------------------

/**
 * Browser WebAuthn client for Privasys enclaves.
 *
 * Handles passkey registration and authentication through the
 * management service FIDO2 proxy endpoint, which forwards requests
 * to the enclave.
 *
 * Usage:
 * ```ts
 * import { WebAuthnClient } from '@privasys/auth';
 *
 * const webauthn = new WebAuthnClient({
 *   apiBase: 'https://api.developer.privasys.org',
 *   appName: 'my-app',
 * });
 *
 * // Register a new passkey
 * const result = await webauthn.register();
 * // result.sessionToken is ready to use as X-App-Auth header
 *
 * // Authenticate with existing passkey
 * const result = await webauthn.authenticate();
 * ```
 */
export class WebAuthnClient {
    readonly config: WebAuthnConfig;
    readonly sessions: SessionManager;
    private events: WebAuthnEvents;
    private state: WebAuthnState = 'idle';

    constructor(config: WebAuthnConfig, events: WebAuthnEvents = {}) {
        this.config = { timeout: 60_000, ...config };
        this.events = events;
        this.sessions = new SessionManager();
    }

    /** Update event handlers. */
    on(events: Partial<WebAuthnEvents>): void {
        this.events = { ...this.events, ...events };
    }

    /** Get the current state. */
    getState(): WebAuthnState {
        return this.state;
    }

    /**
     * Register a new passkey with the enclave.
     *
     * Calls the FIDO2 proxy to get registration options, invokes
     * `navigator.credentials.create()`, then sends the attestation
     * back to the enclave for verification.
     */
    async register(userName?: string): Promise<AuthResult> {
        this.setState('requesting-options');

        try {
            const userHandle = base64urlEncode(
                crypto.getRandomValues(new Uint8Array(32)).buffer,
            );
            const sessionId = randomHex(16);

            // 1. Get standard WebAuthn registration options from the enclave
            const opts = await this.fido2Fetch(
                'register/begin',
                {
                    userName: userName ?? globalThis.location?.hostname ?? 'user',
                    userHandle,
                },
                { session_id: sessionId },
            );

            const publicKey = opts.publicKey;
            if (!publicKey) throw new Error('Missing publicKey in registration options');

            // 2. Build PublicKeyCredentialCreationOptions
            //    Force authenticatorAttachment to "platform" so only the
            //    current device's authenticator (Windows Hello, Touch ID) is
            //    offered.  Cross-device passkeys (phone QR) use the Privasys
            //    Wallet relay flow instead — the CTAP2 hybrid QR protocol is
            //    incompatible with the wallet's custom QR format.
            const createOptions: CredentialCreationOptions = {
                publicKey: {
                    challenge: base64urlDecode(publicKey.challenge),
                    rp: { id: publicKey.rp.id, name: publicKey.rp.name },
                    user: {
                        id: base64urlDecode(publicKey.user.id),
                        name: publicKey.user.name,
                        displayName: publicKey.user.displayName ?? publicKey.user.name,
                    },
                    pubKeyCredParams: (publicKey.pubKeyCredParams ?? []).map(
                        (p: { type?: string; alg: number }) => ({
                            type: (p.type ?? 'public-key') as PublicKeyCredentialType,
                            alg: p.alg,
                        }),
                    ),
                    timeout: this.config.timeout,
                    attestation: (publicKey.attestation ?? 'none') as AttestationConveyancePreference,
                    authenticatorSelection: {
                        authenticatorAttachment: 'platform' as AuthenticatorAttachment,
                        residentKey: (publicKey.authenticatorSelection?.residentKey ?? 'preferred') as ResidentKeyRequirement,
                        userVerification: (publicKey.authenticatorSelection?.userVerification ?? 'preferred') as UserVerificationRequirement,
                    },
                    ...(publicKey.excludeCredentials
                        ? {
                              excludeCredentials: publicKey.excludeCredentials.map(
                                  (c: { id: string }) => ({
                                      type: 'public-key' as const,
                                      id: base64urlDecode(c.id),
                                  }),
                              ),
                          }
                        : {}),
                },
            };

            this.setState('ceremony');

            // 3. Call navigator.credentials.create()
            const credential = (await navigator.credentials.create(
                createOptions,
            )) as PublicKeyCredential | null;

            if (!credential) throw new Error('No credential returned');

            this.setState('verifying');

            // 4. Send standard WebAuthn attestation response to the enclave
            const response = credential.response as AuthenticatorAttestationResponse;
            const result = await this.fido2Fetch(
                'register/complete',
                {
                    id: base64urlEncode(credential.rawId),
                    rawId: base64urlEncode(credential.rawId),
                    type: 'public-key',
                    response: {
                        attestationObject: base64urlEncode(response.attestationObject),
                        clientDataJSON: base64urlEncode(response.clientDataJSON),
                    },
                },
                { challenge: publicKey.challenge },
            );

            return this.complete(result.sessionToken ?? '', sessionId);
        } catch (err) {
            return this.fail(err);
        }
    }

    /**
     * Authenticate with an existing passkey.
     *
     * Calls the FIDO2 proxy to get authentication options, invokes
     * `navigator.credentials.get()`, then sends the assertion back
     * to the enclave for verification.
     */
    async authenticate(): Promise<AuthResult> {
        this.setState('requesting-options');

        try {
            const sessionId = randomHex(16);

            // 1. Get standard WebAuthn authentication options from the enclave
            const opts = await this.fido2Fetch(
                'authenticate/begin',
                {},
                { session_id: sessionId },
            );

            const publicKey = opts.publicKey;
            if (!publicKey) throw new Error('Missing publicKey in authentication options');

            // 2. Build PublicKeyCredentialRequestOptions
            const getOptions: CredentialRequestOptions = {
                publicKey: {
                    challenge: base64urlDecode(publicKey.challenge),
                    rpId: publicKey.rpId,
                    timeout: this.config.timeout,
                    userVerification: (publicKey.userVerification ?? 'preferred') as UserVerificationRequirement,
                    ...(publicKey.allowCredentials?.length
                        ? {
                              allowCredentials: publicKey.allowCredentials.map(
                                  (c: { id: string; transports?: string[] }) => ({
                                      type: 'public-key' as const,
                                      id: base64urlDecode(c.id),
                                      ...(c.transports?.length
                                          ? { transports: c.transports as AuthenticatorTransport[] }
                                          : {}),
                                  }),
                              ),
                          }
                        : {}),
                } as PublicKeyCredentialRequestOptions,
            };

            this.setState('ceremony');

            // 3. Call navigator.credentials.get()
            const assertion = (await navigator.credentials.get(
                getOptions,
            )) as PublicKeyCredential | null;

            if (!assertion) throw new Error('No assertion returned');

            this.setState('verifying');

            // 4. Send standard WebAuthn assertion response to the enclave
            const response = assertion.response as AuthenticatorAssertionResponse;
            const result = await this.fido2Fetch(
                'authenticate/complete',
                {
                    id: base64urlEncode(assertion.rawId),
                    rawId: base64urlEncode(assertion.rawId),
                    type: 'public-key',
                    response: {
                        clientDataJSON: base64urlEncode(response.clientDataJSON),
                        authenticatorData: base64urlEncode(response.authenticatorData),
                        signature: base64urlEncode(response.signature),
                    },
                },
                { challenge: publicKey.challenge },
            );

            return this.complete(result.sessionToken ?? '', sessionId);
        } catch (err) {
            return this.fail(err);
        }
    }

    /**
     * Check if the browser supports WebAuthn.
     */
    static isSupported(): boolean {
        return typeof globalThis.PublicKeyCredential !== 'undefined';
    }

    // ---- internals ----

    private async fido2Fetch(
        action: string,
        body: Record<string, unknown>,
        params?: Record<string, string>,
    ): Promise<Record<string, any>> {
        const base = this.config.apiBase.replace(/\/+$/, '');
        const url = new URL(`${base}/api/v1/apps/${encodeURIComponent(this.config.appName)}/fido2/${action}`);
        if (params) {
            for (const [k, v] of Object.entries(params)) {
                url.searchParams.set(k, v);
            }
        }
        const res = await fetch(url.toString(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ error: res.statusText }));
            throw new Error(err.error ?? `HTTP ${res.status}`);
        }
        return res.json();
    }

    private complete(sessionToken: string, sessionId: string): AuthResult {
        this.setState('complete');

        const result: AuthResult = {
            sessionToken,
            sessionId,
        };

        this.sessions.store({
            token: sessionToken,
            rpId: this.config.appName,
            origin: globalThis.location?.origin ?? '',
            authenticatedAt: Date.now(),
        });

        this.events.onAuthenticated?.(result);
        return result;
    }

    private fail(err: unknown): never {
        this.setState('error');
        const error =
            err instanceof Error
                ? err.name === 'NotAllowedError'
                    ? new Error('Credential operation was cancelled or timed out')
                    : err
                : new Error(String(err));
        this.events.onError?.(error);
        throw error;
    }

    private setState(state: WebAuthnState): void {
        this.state = state;
        this.events.onStateChange?.(state);
    }
}
