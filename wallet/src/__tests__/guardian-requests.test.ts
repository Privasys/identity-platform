// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// The IdP call and the auth store are stand-ins: what is under test is what
// the store believes is waiting, and when it asks.
const mockList = jest.fn();
jest.mock('@/services/recovery-api', () => ({
    listRecoveryRequests: (token: string) => mockList(token),
}));

let mockAccount: { sessionToken: string; sessionExpiresAt: number } | null = null;
jest.mock('@/stores/auth', () => ({
    useAuthStore: { getState: () => ({ privasysId: mockAccount }) },
}));

import { useGuardianRequestsStore, waitingCount } from '@/stores/guardian-requests';

const request = { request_id: 'r1', user_id: 'u1', display_name: 'Ada' };

beforeEach(() => {
    mockList.mockReset();
    mockAccount = null;
    useGuardianRequestsStore.getState().clearAll();
});

describe('what counts as waiting', () => {
    it('is one when only a push has said so', () => {
        expect(waitingCount({ requests: [], heard: false })).toBe(0);
        expect(waitingCount({ requests: [], heard: true })).toBe(1);
        expect(waitingCount({ requests: [request, { ...request, request_id: 'r2' }], heard: true })).toBe(2);
    });
});

describe('refresh', () => {
    it('never asks without a live session, and keeps what the push said', async () => {
        useGuardianRequestsStore.getState().remember();

        await useGuardianRequestsStore.getState().refresh();
        mockAccount = { sessionToken: 'stale', sessionExpiresAt: Date.now() - 1 };
        await useGuardianRequestsStore.getState().refresh();

        expect(mockList).not.toHaveBeenCalled();
        expect(waitingCount(useGuardianRequestsStore.getState())).toBe(1);
    });

    it('takes the list as the truth once it can be read', async () => {
        mockAccount = { sessionToken: 'live', sessionExpiresAt: Date.now() + 60_000 };
        useGuardianRequestsStore.getState().remember();

        mockList.mockResolvedValueOnce({ requests: [request] });
        await useGuardianRequestsStore.getState().refresh();
        expect(mockList).toHaveBeenCalledWith('wallet:live');
        expect(useGuardianRequestsStore.getState().requests).toEqual([request]);
        expect(useGuardianRequestsStore.getState().heard).toBe(false);

        // Answered elsewhere: an empty list clears it.
        mockList.mockResolvedValueOnce({ requests: [] });
        await useGuardianRequestsStore.getState().refresh();
        expect(waitingCount(useGuardianRequestsStore.getState())).toBe(0);
    });

    it('keeps what the push said when the IdP cannot be read', async () => {
        mockAccount = { sessionToken: 'live', sessionExpiresAt: Date.now() + 60_000 };
        useGuardianRequestsStore.getState().remember();
        mockList.mockRejectedValueOnce(new Error('offline'));

        await useGuardianRequestsStore.getState().refresh();
        expect(waitingCount(useGuardianRequestsStore.getState())).toBe(1);
    });
});
