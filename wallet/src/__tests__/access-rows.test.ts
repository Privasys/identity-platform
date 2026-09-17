// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * How the Access tab sorts what the holder has granted.
 *
 * The split is not by kind of data. It is by who can end it: access to data we
 * hold ends when the holder revokes it, and a credential they handed over for
 * an account elsewhere does not, because only they can kill it at the provider.
 * Getting a row into the wrong group would put the wrong promise under the
 * button.
 */

// Storage is in-memory here, as in the other store tests: the module pulls
// in react-native, which this environment does not provide.
jest.mock('@/utils/storage', () => {
    const store: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (key: string) => store[key] ?? null),
        setItemAsync: jest.fn(async (key: string, value: string) => {
            store[key] = value;
        }),
        deleteItemAsync: jest.fn(async (key: string) => {
            delete store[key];
        }),
    };
});

import { capabilityState, type CapabilityRecord } from '@/stores/capabilities';
import { accessRows, groupOf, isLive, liveCount, rowsInGroup } from '@/utils/access-rows';

const NOW = 1_800_000_000;

const grant = (over: Partial<CapabilityRecord> = {}): CapabilityRecord => ({
    appId: 'app-1',
    appName: 'Privasystant',
    resourceAppId: 'res-1',
    resourceAppName: 'Privasys Drive',
    kind: 'storage.folder',
    resourceLabel: 'Harness',
    permissions: ['read', 'write'],
    decision: 'approved',
    capabilityId: 'cap-1',
    grantedAt: NOW - 1000,
    ...over,
});

describe('which group a grant belongs to', () => {
    it('is a connected account when the holder typed a secret into it', () => {
        expect(groupOf(grant({ setupProvided: true }))).toBe('account');
    });

    it('is access to your data otherwise', () => {
        expect(groupOf(grant())).toBe('data');
        expect(groupOf(grant({ setupProvided: false }))).toBe('data');
    });
});

describe('accessRows', () => {
    // A denial is kept so a re-prompt can say the holder declined before. It is
    // not access, so it has no business on a screen about what has access.
    it('leaves out denials', () => {
        const rows = accessRows([grant(), grant({ appId: 'app-2', decision: 'denied' })]);
        expect(rows.map((r) => r.record.appId)).toEqual(['app-1']);
    });

    it('puts the newest first', () => {
        const rows = accessRows([
            grant({ appId: 'old', grantedAt: NOW - 9000 }),
            grant({ appId: 'new', grantedAt: NOW - 10 }),
        ]);
        expect(rows.map((r) => r.record.appId)).toEqual(['new', 'old']);
    });

    // "You removed this on 17 September" is an answer. A row that silently
    // disappears leaves the holder wondering whether they imagined it.
    it('keeps revoked and expired rows', () => {
        const rows = accessRows([
            grant({ appId: 'revoked', revokedAt: NOW - 5 }),
            grant({ appId: 'expired', expiresAt: NOW - 5 }),
        ]);
        expect(rows).toHaveLength(2);
    });

    it('splits the two groups', () => {
        const records = [
            grant({ appId: 'mail', setupProvided: true }),
            grant({ appId: 'harness' }),
        ];
        expect(rowsInGroup(records, 'account').map((r) => r.record.appId)).toEqual(['mail']);
        expect(rowsInGroup(records, 'data').map((r) => r.record.appId)).toEqual(['harness']);
    });
});

describe('isLive', () => {
    it('is true for a grant with no end in sight', () => {
        expect(isLive(grant({ expiresAt: NOW + 1000 }), NOW)).toBe(true);
        expect(isLive(grant(), NOW)).toBe(true);
    });

    it.each([
        ['revoked', { revokedAt: NOW - 1 }],
        ['expired', { expiresAt: NOW - 1 }],
        ['gone from the service', { checkResult: 'gone' as const }],
    ])('is false when %s', (_why, over) => {
        expect(isLive(grant(over), NOW)).toBe(false);
    });

    it('counts only the live ones for a section', () => {
        const records = [
            grant({ appId: 'a', setupProvided: true }),
            grant({ appId: 'b', setupProvided: true, revokedAt: NOW - 1 }),
        ];
        expect(liveCount(records, 'account', NOW)).toBe(1);
    });
});

describe('capabilityState', () => {
    // The distinction the screen exists to make. A record the wallet has never
    // managed to confirm is not the same claim as one the service just agreed
    // to, and collapsing them would make the list assert things it cannot know.
    it('separates what the service confirmed from what this device remembers', () => {
        expect(capabilityState(grant({ checkResult: 'held' }), NOW)).toBe('confirmed');
        expect(capabilityState(grant(), NOW)).toBe('unconfirmed');
    });

    it('reports a grant the service no longer knows about', () => {
        expect(capabilityState(grant({ checkResult: 'gone' }), NOW)).toBe('gone');
    });

    // Revoked outranks everything: it is what the holder did, and it is the
    // answer they are looking for when they come back to check.
    it('reports the holder’s own revocation ahead of anything else', () => {
        expect(
            capabilityState(grant({ revokedAt: NOW - 1, checkResult: 'held', expiresAt: NOW - 1 }), NOW),
        ).toBe('revoked');
    });

    it('reports expiry when nothing else has happened', () => {
        expect(capabilityState(grant({ expiresAt: NOW - 1 }), NOW)).toBe('expired');
    });
});
