// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('@/services/privasys-id', () => ({ ensurePrivasysSession: jest.fn() }));
jest.mock('@/services/identities', () => ({}));
jest.mock('@/services/devices', () => ({}));
jest.mock('@/utils/storage', () => ({}));
jest.mock('@/i18n', () => ({ currentLocale: () => 'en-GB' }));

import { deletionMessage } from '@/services/account-deletion';

// The IdP verifies exactly these bytes (its joinMessage plus the tail), so the
// layout is pinned here: info 0 user_id 0 || raw challenge || 0 action 0 delete_at.
describe('account deletion message', () => {
    const challenge = new Uint8Array([0, 1, 2, 255]);
    const text = (b: Uint8Array) => Array.from(b);
    const utf8 = (s: string) => Array.from(new TextEncoder().encode(s));

    it('signs a schedule with its exact date', () => {
        const m = deletionMessage('dXNlcg', challenge, 'schedule', '2026-11-28T15:00:00Z');
        expect(text(m)).toEqual([
            ...utf8('privasys-account-deletion/v1\x00dXNlcg\x00'),
            0, 1, 2, 255,
            ...utf8('\x00schedule\x002026-11-28T15:00:00Z'),
        ]);
    });

    it('signs a cancel with an empty date', () => {
        const m = deletionMessage('dXNlcg', challenge, 'cancel', '');
        expect(text(m).slice(-8)).toEqual(utf8('\x00cancel\x00'));
    });
});
