// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { relaySessionToken } from '../services/broker';

/**
 * Minimal WebSocket stub for testing the relay handshake.
 */
class FakeWebSocket {
    static instances: FakeWebSocket[] = [];

    onopen: (() => void) | null = null;
    onmessage: ((e: { data: string }) => void) | null = null;
    onerror: ((e: unknown) => void) | null = null;
    onclose: (() => void) | null = null;

    sent: string[] = [];
    closed = false;
    url: string;

    constructor(url: string) {
        this.url = url;
        FakeWebSocket.instances.push(this);
        // Simulate async open
        setTimeout(() => this.onopen?.(), 0);
    }

    send(data: string) {
        this.sent.push(data);
    }

    close() {
        this.closed = true;
        setTimeout(() => this.onclose?.(), 0);
    }
}

beforeEach(() => {
    FakeWebSocket.instances = [];
    (globalThis as any).WebSocket = FakeWebSocket;
});

afterEach(() => {
    delete (globalThis as any).WebSocket;
});

describe('relaySessionToken', () => {
    it('sends auth-result immediately on open (browser-first / QR flow)', async () => {
        const promise = relaySessionToken(
            'wss://broker.example.com/relay',
            'sess-123',
            'tok-abc',
            'push-xyz'
        );

        // Wait for WebSocket to "open"
        await tick();
        const ws = FakeWebSocket.instances[0];
        expect(ws).toBeDefined();

        // auth-result sent immediately on open
        expect(ws.sent).toHaveLength(1);

        const authMsg = JSON.parse(ws.sent[0]);
        expect(authMsg).toEqual({
            type: 'auth-result',
            sessionToken: 'tok-abc',
            pushToken: 'push-xyz',
        });

        // Should close after sending
        expect(ws.closed).toBe(true);

        await promise;
    });

    it('does NOT wrap session token in a payload object', async () => {
        const promise = relaySessionToken(
            'wss://broker.example.com/relay',
            'sess-456',
            'tok-def',
            null
        );

        await tick();
        const ws = FakeWebSocket.instances[0];

        const authMsg = JSON.parse(ws.sent[0]);
        // Must NOT have a payload wrapper
        expect(authMsg.payload).toBeUndefined();
        expect(authMsg.sessionToken).toBe('tok-def');
        expect(authMsg.pushToken).toBeNull();

        await promise;
    });

    it('sends the device label beside the push token, trimmed and capped at 80', async () => {
        const promise = relaySessionToken(
            'wss://broker.example.com/relay',
            'sess-789',
            'tok-ghi',
            'push-xyz',
            undefined,
            undefined,
            '  ' + 'x'.repeat(100) + '  ',
        );

        await tick();
        const authMsg = JSON.parse(FakeWebSocket.instances[0].sent[0]);
        expect(authMsg.pushToken).toBe('push-xyz');
        expect(authMsg.deviceLabel).toBe('x'.repeat(80));

        await promise;
    });

    it('omits a blank device label', async () => {
        const promise = relaySessionToken('wss://broker.example.com/relay', 'sess-790', 'tok-jkl', null, undefined, undefined, '   ');

        await tick();
        const authMsg = JSON.parse(FakeWebSocket.instances[0].sent[0]);
        expect('deviceLabel' in authMsg).toBe(false);

        await promise;
    });

    it('sends on browser-waiting if open has not yet sent (wallet-first / push flow)', async () => {
        // WebSocket that never auto-opens — simulates wallet connecting
        // before browser, so onopen fires but browser isn't there yet.
        // Instead, we skip onopen and only deliver browser-waiting.
        let capturedWs: any;
        (globalThis as any).WebSocket = class {
            onopen: (() => void) | null = null;
            onmessage: ((e: { data: string }) => void) | null = null;
            onerror: ((e: unknown) => void) | null = null;
            onclose: (() => void) | null = null;
            sent: string[] = [];
            closed = false;
            url: string;
            constructor(url: string) {
                this.url = url;
                capturedWs = this;
                // Do NOT auto-fire onopen
            }
            send(data: string) { this.sent.push(data); }
            close() { this.closed = true; setTimeout(() => this.onclose?.(), 0); }
        };

        const promise = relaySessionToken(
            'wss://broker.example.com/relay',
            'sess-push',
            'tok-push',
            'push-tok'
        );
        await tick();

        // Simulate browser-waiting (hub notifies wallet that browser arrived)
        capturedWs.onmessage?.({ data: JSON.stringify({ type: 'browser-waiting' }) });
        await tick();

        expect(capturedWs.sent).toHaveLength(1);
        const msg = JSON.parse(capturedWs.sent[0]);
        expect(msg.type).toBe('auth-result');
        expect(msg.sessionToken).toBe('tok-push');
        expect(capturedWs.closed).toBe(true);

        await promise;
    });

    it('sends auth-result message type on open', async () => {
        const promise = relaySessionToken(
            'wss://broker.example.com/relay',
            's1',
            't1',
            null
        );

        await tick();
        const ws = FakeWebSocket.instances[0];

        const msg = JSON.parse(ws.sent[0]);
        expect(msg.type).toBe('auth-result');

        await promise;
    });

    it('constructs WebSocket URL with session and role params', async () => {
        const promise = relaySessionToken(
            'wss://broker.example.com/relay',
            'my-session',
            't',
            null
        );

        await tick();
        const ws = FakeWebSocket.instances[0];

        expect(ws.url).toBe(
            'wss://broker.example.com/relay?session=my-session&role=wallet'
        );

        await promise;
    });

    it('rejects on WebSocket error before open', async () => {
        // Override WebSocket to fire onerror instead of onopen
        (globalThis as any).WebSocket = class extends FakeWebSocket {
            constructor(url: string) {
                super(url);
                // Replace the auto-open with an error
                const self = this;
                // Clear the setTimeout that fires onopen
                FakeWebSocket.instances.push(self);
            }
        };
        // Re-assign so our subclass is used, but prevent double-push
        const origInstances = FakeWebSocket.instances;
        FakeWebSocket.instances = [];

        (globalThis as any).WebSocket = class {
            onopen: (() => void) | null = null;
            onmessage: ((e: { data: string }) => void) | null = null;
            onerror: ((e: unknown) => void) | null = null;
            onclose: (() => void) | null = null;
            sent: string[] = [];
            closed = false;
            url: string;
            constructor(url: string) {
                this.url = url;
                // Fire error instead of open
                setTimeout(() => this.onerror?.({} as any), 0);
            }
            send(data: string) { this.sent.push(data); }
            close() { this.closed = true; setTimeout(() => this.onclose?.(), 0); }
        };

        const promise = relaySessionToken(
            'wss://broker.example.com/relay',
            's',
            't',
            null
        );

        await expect(promise).rejects.toThrow('Broker WebSocket error');
    });

    it('rejects with timeout when open never fires', async () => {
        jest.useFakeTimers();

        // WebSocket that never opens
        (globalThis as any).WebSocket = class {
            onopen: (() => void) | null = null;
            onmessage: ((e: { data: string }) => void) | null = null;
            onerror: ((e: unknown) => void) | null = null;
            onclose: (() => void) | null = null;
            sent: string[] = [];
            closed = false;
            url: string;
            constructor(url: string) { this.url = url; }
            send(data: string) { this.sent.push(data); }
            close() {
                this.closed = true;
                // onclose fires synchronously in the timeout handler
                this.onclose?.();
            }
        };

        const promise = relaySessionToken(
            'wss://broker.example.com/relay',
            's',
            't',
            null
        );

        // Fast-forward past the 15s timeout
        jest.advanceTimersByTime(16_000);

        await expect(promise).rejects.toThrow('Broker relay timed out');

        jest.useRealTimers();
    });
});

/** Flush microtasks + one setTimeout round. */
function tick(): Promise<void> {
    return new Promise((r) => setTimeout(r, 0));
}
