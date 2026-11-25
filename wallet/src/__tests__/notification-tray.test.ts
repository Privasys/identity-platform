// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What leaves the notification tray, and the number on the app's icon.
 */

jest.mock('react-native', () => ({ Platform: { OS: 'ios' } }));

const mockDismiss = jest.fn(async (_id: string) => undefined);
const mockBadge = jest.fn(async (_n: number) => true);
let mockPresented: { request: { identifier: string; content: { data: Record<string, unknown> } }; date: number }[] = [];
jest.mock('expo-notifications', () => ({
    getPresentedNotificationsAsync: jest.fn(async () => mockPresented),
    dismissNotificationAsync: (id: string) => mockDismiss(id),
    setBadgeCountAsync: (n: number) => mockBadge(n),
}));

jest.mock('../services/devices', () => ({
    ensureDevice: jest.fn(async () => ({ id: 'device', secret: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc' })),
}));

import { dismissClosed, requestAnswered, setAppBadge, setOwnPushToken } from '../services/notification-dismiss';

const shown = (identifier: string, data: Record<string, unknown>) => ({
    request: { identifier, content: { data } },
    date: Date.now(),
});
const settle = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
    mockDismiss.mockClear();
    mockBadge.mockClear();
    mockPresented = [];
    setOwnPushToken(null);
    (global as any).fetch = jest.fn(async () => ({ ok: true, status: 200 }));
});

describe('notifications for requests that are closed', () => {
    it('go, and the ones still open stay', async () => {
        mockPresented = [
            shown('a', { type: 'vault-approval', vault_op: 'open-1' }),
            shown('b', { type: 'vault-approval', vault_op: 'closed-1' }),
            shown('c', { type: 'vault-approval-batch', batch_id: 'closed-batch' }),
            shown('d', { type: 'vault-approval-batch', batch_id: 'open-batch' }),
        ];
        const n = await dismissClosed({
            'vault-approval': new Set(['open-1']),
            'vault-approval-batch': new Set(['open-batch']),
        });
        expect(n).toBe(2);
        expect(mockDismiss.mock.calls.map((c) => c[0]).sort()).toEqual(['b', 'c']);
    });

    it('leave alone a kind nobody asked about, and one naming no request', async () => {
        mockPresented = [
            shown('a', { type: 'auth-request', sessionId: 's' }),
            shown('b', { type: 'recovery-request' }),
            shown('c', { type: 'vault-approval' }),
        ];
        expect(await dismissClosed({ 'vault-approval': new Set() })).toBe(0);
        expect(mockDismiss).not.toHaveBeenCalled();
    });
});

describe('a request answered in the wallet', () => {
    it('clears its notification here and tells the other phones', async () => {
        setOwnPushToken('ExponentPushToken[me]');
        mockPresented = [shown('a', { type: 'vault-approval', vault_op: 'op-1' }), shown('b', { type: 'vault-approval', vault_op: 'op-2' })];
        requestAnswered('vault-approval', 'op-1');
        await settle();
        await settle();
        expect(mockDismiss.mock.calls.map((c) => c[0])).toEqual(['a']);
        const call = ((global as any).fetch as jest.Mock).mock.calls[0];
        expect(call[0]).toMatch(/\/push\/dismiss$/);
        const body = JSON.parse(call[1].body);
        expect(body.push_token).toBe('ExponentPushToken[me]');
        // Signed by this phone: a push token alone is not a secret.
        expect(body.sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
        expect(body.issued_at).toBeGreaterThan(0);
        // The request's id does not travel: only the key derived from it.
        expect(JSON.stringify(body)).not.toContain('op-1');
    });

    it('still clears this phone when there is no token to name the others by', async () => {
        mockPresented = [shown('a', { type: 'vault-approval-batch', batch_id: 'batch-1' })];
        requestAnswered('vault-approval-batch', 'batch-1');
        await settle();
        await settle();
        expect(mockDismiss.mock.calls.map((c) => c[0])).toEqual(['a']);
        expect((global as any).fetch).not.toHaveBeenCalled();
    });

    it('does nothing for a kind it does not know', async () => {
        requestAnswered('something-else', 'x');
        await settle();
        expect(mockDismiss).not.toHaveBeenCalled();
        expect((global as any).fetch).not.toHaveBeenCalled();
    });
});

describe('the number on the icon', () => {
    it('is what is waiting, never negative, capped', async () => {
        await setAppBadge(3);
        await setAppBadge(0);
        await setAppBadge(-2);
        await setAppBadge(500);
        expect(mockBadge.mock.calls.map((c) => c[0])).toEqual([3, 0, 0, 99]);
    });
});
