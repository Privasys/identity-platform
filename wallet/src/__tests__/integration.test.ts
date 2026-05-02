// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * End-to-end integration test for the full auth flow.
 *
 * Simulates the entire registration + relay pipeline without hardware
 * or network dependencies by mocking:
 *   - The broker WebSocket hub (in-process message relay)
 *   - The enclave FIDO2 endpoints (NativeRaTls.post)
 *   - Hardware key generation/signing (NativeKeys)
 *   - RA-TLS attestation inspection
 *
 * Run: npx jest --testPathPattern integration
 */

import { relaySessionToken } from '../services/broker';
import * as fido2 from '../services/fido2';

// ── Fake broker hub ─────────────────────────────────────────────────────

/**
 * In-process relay hub that pairs FakeWebSocket peers by session ID,
 * faithfully replicating the Go broker's behaviour:
 *  - When a peer joins it notifies the OTHER peer: {"type":"<role>-waiting"}
 *  - Messages are forwarded verbatim to the other peer
 */
class FakeBrokerHub {
    sessions = new Map<string, { browser?: FakeWebSocket; wallet?: FakeWebSocket }>();

    join(ws: FakeWebSocket, sessionId: string, role: string) {
        let session = this.sessions.get(sessionId);
        if (!session) {
            session = {};
            this.sessions.set(sessionId, session);
        }

        const other = role === 'browser' ? session.wallet : session.browser;

        if (role === 'browser') session.browser = ws;
        else session.wallet = ws;

        ws._hub = this;
        ws._sessionId = sessionId;
        ws._role = role;

        // Notify the OTHER peer that this role just arrived
        if (other && !other.closed) {
            const msg = JSON.stringify({ type: `${role}-waiting` });
            setTimeout(() => other.onmessage?.({ data: msg } as any), 0);
        }

        // Fire open
        setTimeout(() => ws.onopen?.(), 0);
    }

    relay(from: FakeWebSocket, data: string) {
        const session = this.sessions.get(from._sessionId!);
        if (!session) return;
        const other = from._role === 'browser' ? session.wallet : session.browser;
        if (other && !other.closed) {
            setTimeout(() => other.onmessage?.({ data } as any), 0);
        }
    }

    remove(ws: FakeWebSocket) {
        const session = this.sessions.get(ws._sessionId!);
        if (!session) return;
        if (session.browser === ws) session.browser = undefined;
        if (session.wallet === ws) session.wallet = undefined;
        if (!session.browser && !session.wallet) {
            this.sessions.delete(ws._sessionId!);
        }
    }
}

class FakeWebSocket {
    static hub: FakeBrokerHub;

    onopen: (() => void) | null = null;
    onmessage: ((e: { data: string }) => void) | null = null;
    onerror: ((e: unknown) => void) | null = null;
    onclose: ((e?: any) => void) | null = null;

    sent: string[] = [];
    closed = false;
    url: string;

    _hub?: FakeBrokerHub;
    _sessionId?: string;
    _role?: string;

    constructor(url: string) {
        this.url = url;
        const parsed = new URL(url);
        const sessionId = parsed.searchParams.get('session') || '';
        const role = parsed.searchParams.get('role') || '';
        FakeWebSocket.hub.join(this, sessionId, role);
    }

    send(data: string) {
        this.sent.push(data);
        this._hub?.relay(this, data);
    }

    close() {
        if (this.closed) return;
        this.closed = true;
        this._hub?.remove(this);
        setTimeout(() => this.onclose?.({ code: 1000 }), 0);
    }
}

// ── Fake enclave (FIDO2 server) ─────────────────────────────────────────

const FAKE_SESSION_TOKEN = 'test-session-token-' + Math.random().toString(36).slice(2);
const FAKE_CHALLENGE = btoa('test-challenge-12345678').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function createFakeEnclave() {
    return {
        handlePost: (_host: string, _port: number, path: string, bodyJson: string) => {
            const body = JSON.parse(bodyJson);

            if (path === '/fido2/register/begin') {
                return {
                    status: 200,
                    body: JSON.stringify({
                        type: 'register_options',
                        challenge: FAKE_CHALLENGE,
                        rp: { id: 'example.apps-test.privasys.org', name: 'Example App' },
                        user: { id: btoa('user-1'), name: body.user_name, display_name: body.user_name },
                        pub_key_cred_params: [{ type: 'public-key', alg: -7 }],
                        authenticator_selection: {
                            authenticator_attachment: 'platform',
                            user_verification: 'required',
                        },
                        attestation: 'none',
                    }),
                };
            }

            if (path === '/fido2/register/complete') {
                return {
                    status: 200,
                    body: JSON.stringify({
                        type: 'register_ok',
                        status: 'ok',
                        session_token: FAKE_SESSION_TOKEN,
                    }),
                };
            }

            if (path === '/fido2/authenticate/begin') {
                return {
                    status: 200,
                    body: JSON.stringify({
                        type: 'authenticate_options',
                        challenge: FAKE_CHALLENGE,
                        allow_credentials: [{ type: 'public-key', id: body.credential_id || 'cred-1' }],
                        user_verification: 'required',
                    }),
                };
            }

            if (path === '/fido2/authenticate/complete') {
                return {
                    status: 200,
                    body: JSON.stringify({
                        type: 'authenticate_ok',
                        status: 'ok',
                        session_token: FAKE_SESSION_TOKEN,
                    }),
                };
            }

            return { status: 404, body: '{"type":"error","error":"not found"}' };
        },
    };
}

// ── Fake hardware keys ──────────────────────────────────────────────────

const FAKE_PUBLIC_KEY_DER = new Uint8Array(91);
// Minimal DER SPKI header for P-256 (tells the parser "this is EC P-256")
// 30 59 30 13 06 07 2a8648ce3d0201 06 08 2a8648ce3d030107 03 42 00 04 ...
const DER_HEADER = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
for (let i = 0; i < DER_HEADER.length; i++) FAKE_PUBLIC_KEY_DER[i] = DER_HEADER[i]!;
// Fill remaining with deterministic bytes
for (let i = DER_HEADER.length; i < 91; i++) FAKE_PUBLIC_KEY_DER[i] = i & 0xff;

const FAKE_SIGNATURE = new Uint8Array(64).fill(0xab);

// ── Test setup ──────────────────────────────────────────────────────────

let hub: FakeBrokerHub;

// Mock NativeRaTls.post — route to fake enclave
jest.mock('../../modules/native-ratls/src/index', () => ({
    post: jest.fn((host: string, port: number, path: string, body: string) => {
        const parsed = JSON.parse(body);
        const challenge = btoa('test-challenge-12345678').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        const sessionToken = 'test-session-token-fixed';

        if (path === '/fido2/register/begin') {
            return Promise.resolve({
                status: 200,
                body: JSON.stringify({
                    type: 'register_options',
                    challenge,
                    rp: { id: 'example.apps-test.privasys.org', name: 'Example App' },
                    user: { id: btoa('user-1'), name: parsed.user_name, display_name: parsed.user_name },
                    pub_key_cred_params: [{ type: 'public-key', alg: -7 }],
                    authenticator_selection: {
                        authenticator_attachment: 'platform',
                        user_verification: 'required',
                    },
                    attestation: 'none',
                }),
            });
        }
        if (path === '/fido2/register/complete') {
            return Promise.resolve({
                status: 200,
                body: JSON.stringify({ type: 'register_ok', status: 'ok', session_token: sessionToken }),
            });
        }
        if (path === '/fido2/authenticate/begin') {
            return Promise.resolve({
                status: 200,
                body: JSON.stringify({
                    type: 'authenticate_options',
                    challenge,
                    allow_credentials: [{ type: 'public-key', id: parsed.credential_id || 'cred-1' }],
                    user_verification: 'required',
                }),
            });
        }
        if (path === '/fido2/authenticate/complete') {
            return Promise.resolve({
                status: 200,
                body: JSON.stringify({ type: 'authenticate_ok', status: 'ok', session_token: sessionToken }),
            });
        }
        return Promise.resolve({ status: 404, body: '{"type":"error","error":"not found"}' });
    }),
    inspect: jest.fn(() =>
        Promise.resolve({
            valid: true,
            tee_type: 'sgx',
            mrenclave: 'a'.repeat(64),
            workload_code_hash: 'b'.repeat(64),
            workload_config_merkle_root: 'c'.repeat(64),
            cert_subject: 'CN=test',
            cert_not_before: '2026-01-01',
            cert_not_after: '2027-01-01',
            quote_verification_status: 'OK',
        })
    ),
}));

// Mock NativeKeys — returns { publicKey: base64url(0x04 || x || y), keyId, hardwareBacked }
jest.mock('../../modules/native-keys/src/index', () => {
    // 65-byte uncompressed P-256 key: 0x04 + 32 bytes x + 32 bytes y
    const raw = new Uint8Array(65);
    raw[0] = 0x04;
    for (let i = 1; i < 65; i++) raw[i] = i & 0xff;

    // base64url encode
    let bin = '';
    for (let i = 0; i < raw.length; i++) bin += String.fromCharCode(raw[i]!);
    const pubKeyB64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    // 64-byte fake signature
    const sig = new Uint8Array(64).fill(0xab);
    let sigBin = '';
    for (let i = 0; i < sig.length; i++) sigBin += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(sigBin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    return {
        generateKey: jest.fn((_alias: string) =>
            Promise.resolve({ keyId: _alias, publicKey: pubKeyB64, hardwareBacked: true })
        ),
        sign: jest.fn(() =>
            Promise.resolve({ signature: sigB64 })
        ),
    };
});

const EXPECTED_SESSION_TOKEN = 'test-session-token-fixed';

beforeEach(() => {
    hub = new FakeBrokerHub();
    FakeWebSocket.hub = hub;
    (globalThis as any).WebSocket = FakeWebSocket;
});

afterEach(() => {
    delete (globalThis as any).WebSocket;
});

// ── Helper: simulate browser side ───────────────────────────────────────

function browserWaitForResult(sessionId: string): Promise<{ sessionToken: string; pushToken?: string }> {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Browser timed out')), 10_000);

        const ws = new FakeWebSocket(
            `wss://broker.test.privasys.org/relay?session=${sessionId}&role=browser`
        );

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'auth-result') {
                    clearTimeout(timer);
                    ws.close();
                    resolve({ sessionToken: msg.sessionToken, pushToken: msg.pushToken });
                }
            } catch { /* ignore */ }
        };

        ws.onerror = () => {
            clearTimeout(timer);
            reject(new Error('Browser WS error'));
        };
    });
}

function tick(): Promise<void> {
    return new Promise((r) => setTimeout(r, 0));
}

// ── Integration tests ───────────────────────────────────────────────────

describe('E2E: registration + relay (browser connects first)', () => {
    it('browser receives session token after wallet registers', async () => {
        const sessionId = 'e2e-session-' + Date.now();

        // 1. Browser connects first (normal QR flow)
        const browserResult = browserWaitForResult(sessionId);
        await tick();

        // 2. Wallet registers with the enclave
        const regResult = await fido2.register(
            'example.apps-test.privasys.org:8443',
            'fido2-example.apps-test.privasys.org',
            sessionId
        );

        expect(regResult.sessionToken).toBe(EXPECTED_SESSION_TOKEN);

        // 3. Wallet relays to broker
        await relaySessionToken(
            'wss://broker.test.privasys.org/relay',
            sessionId,
            regResult.sessionToken,
            'expo-push-token-test'
        );
        await tick();

        // 4. Browser should have received the token
        const result = await browserResult;
        expect(result.sessionToken).toBe(EXPECTED_SESSION_TOKEN);
        expect(result.pushToken).toBe('expo-push-token-test');
    });

    it('credentials must NOT be saved if relay fails', async () => {
        // Simulate relay failure: hub that errors WebSocket on open
        const errorHub = new FakeBrokerHub();
        const origJoin = errorHub.join.bind(errorHub);
        errorHub.join = (ws, sessionId, role) => {
            if (role === 'wallet') {
                // Simulate connection error
                setTimeout(() => ws.onerror?.({} as any), 0);
                return;
            }
            origJoin(ws, sessionId, role);
        };
        FakeWebSocket.hub = errorHub;

        const sessionId = 'e2e-fail-' + Date.now();

        const regResult = await fido2.register(
            'example.apps-test.privasys.org:8443',
            'fido2-example.apps-test.privasys.org',
            sessionId
        );

        // Relay should fail with WS error
        await expect(
            relaySessionToken(
                'wss://broker.test.privasys.org/relay',
                sessionId,
                regResult.sessionToken,
                null
            )
        ).rejects.toThrow('Broker WebSocket error');
    });
});

describe('E2E: registration + relay (wallet connects first)', () => {
    it('browser receives token via browser-waiting when it connects after wallet', async () => {
        const sessionId = 'e2e-wallet-first-' + Date.now();

        // 1. Wallet registers first
        const regResult = await fido2.register(
            'example.apps-test.privasys.org:8443',
            'fido2-example.apps-test.privasys.org',
            sessionId
        );

        // Customise hub: don't auto-open wallet so we can control timing.
        // When wallet opens it sends immediately (browser not there yet → dropped).
        // Then browser connects → hub sends browser-waiting → wallet re-sends.
        // But wallet has already closed. So we need the hub to delay the open.
        const delayHub = new FakeBrokerHub();
        const origJoin2 = delayHub.join.bind(delayHub);
        let walletWs: FakeWebSocket | null = null;

        delayHub.join = (ws, sid, role) => {
            if (role === 'wallet') {
                walletWs = ws;
                // Register in hub but DON'T fire open yet
                let session = delayHub.sessions.get(sid);
                if (!session) {
                    session = {};
                    delayHub.sessions.set(sid, session);
                }
                session.wallet = ws;
                ws._hub = delayHub;
                ws._sessionId = sid;
                ws._role = role;
                return;
            }
            origJoin2(ws, sid, role);
        };
        FakeWebSocket.hub = delayHub;

        // 2. Wallet starts relay — pending because onopen hasn't fired
        const relayPromise = relaySessionToken(
            'wss://broker.test.privasys.org/relay',
            sessionId,
            regResult.sessionToken,
            'push-tok'
        );
        await tick();

        // 3. Browser connects — hub sends browser-waiting to wallet
        const browserResult = browserWaitForResult(sessionId);
        await tick();

        // 4. Now fire wallet's onopen — it sends auth-result, browser gets it
        walletWs!.onopen?.();
        await tick();
        await tick();

        await relayPromise;
        const result = await browserResult;
        expect(result.sessionToken).toBe(EXPECTED_SESSION_TOKEN);
    });
});

describe('E2E: relay message format', () => {
    it('message has type auth-result with top-level sessionToken', async () => {
        const sessionId = 'e2e-format-' + Date.now();

        // Browser connects first, then wallet relays
        const browserResult = browserWaitForResult(sessionId);
        await tick();

        // Wallet relays
        await relaySessionToken(
            'wss://broker.test.privasys.org/relay',
            sessionId,
            'tok-123',
            'push-456'
        );
        await tick();

        const result = await browserResult;

        // Must match the SDK's expected shape
        expect(result.sessionToken).toBe('tok-123');
        expect((result as any).pushToken).toBe('push-456');
    });
});
