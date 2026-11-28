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

import { isClosed, requestAnswered, setAppBadge } from '../services/notification-dismiss';
import { setPushToken } from '../services/push-token';

const shown = (identifier: string, data: Record<string, unknown>) => ({
    request: { identifier, content: { data } },
    date: Date.now(),
});
const settle = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
    mockDismiss.mockClear();
    mockBadge.mockClear();
    mockPresented = [];
    setPushToken(null);
    (global as any).fetch = jest.fn(async () => ({ ok: true, status: 200 }));
});

describe('a notification for a request', () => {
    const open = {
        'vault-approval': new Set(['open-1']),
        'vault-approval-batch': new Set(['open-batch']),
    };

    it('privasys.id no longer reports open is closed, and one still open is not', () => {
        expect(isClosed({ type: 'vault-approval', vault_op: 'closed-1' }, open)).toBe(true);
        expect(isClosed({ type: 'vault-approval', vault_op: 'open-1' }, open)).toBe(false);
        expect(isClosed({ type: 'vault-approval-batch', batch_id: 'closed-batch' }, open)).toBe(true);
        expect(isClosed({ type: 'vault-approval-batch', batch_id: 'open-batch' }, open)).toBe(false);
    });

    it('of a kind nobody asked about, or naming no request, is not judged', () => {
        expect(isClosed({ type: 'auth-request', sessionId: 's' }, open)).toBe(false);
        expect(isClosed({ type: 'recovery-request' }, open)).toBe(false);
        expect(isClosed({ type: 'vault-approval' }, { 'vault-approval': new Set() })).toBe(false);
    });
});

describe('a request answered in the wallet', () => {
    it('clears its notification here and tells the other phones', async () => {
        setPushToken('ExponentPushToken[me]');
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

    it('is cleared once, however often it is answered', async () => {
        setPushToken('ExponentPushToken[me]');
        mockPresented = [shown('a', { type: 'vault-approval', vault_op: 'op-twice' })];
        requestAnswered('vault-approval', 'op-twice');
        requestAnswered('vault-approval', 'op-twice');
        await settle();
        await settle();
        expect(mockDismiss).toHaveBeenCalledTimes(1);
        expect((global as any).fetch).toHaveBeenCalledTimes(1);
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
