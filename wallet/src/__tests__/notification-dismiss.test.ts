// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('react-native', () => ({ Platform: { OS: 'ios' } }));

import {
    backgroundPushData,
    isStale,
    notificationKey,
    STALE_AFTER_MS,
} from '../services/notification-dismiss';

describe('notificationKey', () => {
    it('is the same on every phone for one request, whatever else the push carries', () => {
        const a = notificationKey({ type: 'auth-request', sessionId: 's-1', clientIP: '1.2.3.4' });
        const b = notificationKey({ type: 'auth-request', sessionId: 's-1', clientIP: '5.6.7.8' });
        expect(a).toBe(b);
        expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
    });

    it('tells requests and types apart', () => {
        const keys = [
            notificationKey({ type: 'auth-request', sessionId: 's-1' }),
            notificationKey({ type: 'auth-request', sessionId: 's-2' }),
            notificationKey({ type: 'voucher-request', sessionId: 's-1' }),
            notificationKey({ type: 'vault-approval', vault_op: 's-1' }),
            notificationKey({ type: 'vault-approval-batch', batch_id: 's-1' }),
            notificationKey({ type: 'attribute-approval', approval: 's-1' }),
            notificationKey({ type: 'capability-request', nonce: 's-1' }),
            notificationKey({ type: 'approval', message_id: 's-1' }),
            notificationKey({ type: 'app-form', message_id: 's-1' }),
            notificationKey({ type: 'app-message', message_id: 's-1' }),
        ];
        expect(keys.every((k) => typeof k === 'string')).toBe(true);
        expect(new Set(keys).size).toBe(keys.length);
    });

    it('does not carry the request id', () => {
        const id = 'vault-capability-that-must-not-travel';
        expect(notificationKey({ type: 'vault-approval', vault_op: id })).not.toContain(id.slice(0, 8));
    });

    it('is null for a notification naming no request', () => {
        expect(notificationKey({ type: 'recovery-request' })).toBeNull();
        expect(notificationKey({ type: 'share-request', sealed: 'x' })).toBeNull();
        expect(notificationKey({ type: 'vault-approval' })).toBeNull();
        expect(notificationKey(undefined)).toBeNull();
    });
});

describe('isStale', () => {
    const now = 1_800_000_000_000;
    it('drops a sign-in or approval once it can no longer be answered', () => {
        expect(isStale({ type: 'auth-request' }, now - STALE_AFTER_MS - 1, now)).toBe(true);
        expect(isStale({ type: 'vault-approval' }, now - STALE_AFTER_MS - 1, now)).toBe(true);
        expect(isStale({ type: 'auth-request' }, now - 60_000, now)).toBe(false);
    });
    it('keeps messages, forms and anything without a date', () => {
        expect(isStale({ type: 'app-message' }, now - 7 * 24 * 3600_000, now)).toBe(false);
        expect(isStale({ type: 'approval' }, now - 7 * 24 * 3600_000, now)).toBe(false);
        expect(isStale({ type: 'auth-request' }, 0, now)).toBe(false);
    });
});

describe('backgroundPushData', () => {
    const push = { type: 'notification-dismiss', key: 'AbCdEfGhIjKlMnOpQrStUv' };
    it('reads the data however the task is handed it', () => {
        expect(backgroundPushData({ data: { dataString: JSON.stringify(push) } })).toEqual(push);
        expect(backgroundPushData({ data: { body: JSON.stringify(push) } })).toEqual(push);
        expect(backgroundPushData({ data: { body: push } })).toEqual(push);
        expect(backgroundPushData({ data: push })).toEqual(push);
    });
    it('is null for a tap or garbage', () => {
        expect(backgroundPushData({ actionIdentifier: 'x', notification: {} })).toBeNull();
        expect(backgroundPushData({ data: { dataString: '{not json' } })).toBeNull();
        expect(backgroundPushData(null)).toBeNull();
    });
});
