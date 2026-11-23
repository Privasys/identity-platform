// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// A list privasys.id could not give says so, rather than looking like
// nothing waiting, and Try again loads it with a token it may mint.

const mockCall = jest.fn();
const mockHasIdentity = jest.fn(() => true);
jest.mock('@/services/platform-token', () => ({
    callWithPlatformToken: (...a: unknown[]) => mockCall(...a),
    hasPlatformIdentity: () => mockHasIdentity(),
}));

import { oneLoadAtATime } from '@/services/idp-list';
import { useCapabilityAsksStore } from '@/stores/capability-asks';

const ok = (body: unknown) => ({ res: { ok: true, status: 200, json: async () => body }, token: 't' });

beforeEach(() => {
    mockCall.mockReset();
    mockHasIdentity.mockReturnValue(true);
    useCapabilityAsksStore.getState().clearAll();
    jest.spyOn(console, 'warn').mockImplementation(() => {});
});

describe('access requests list', () => {
    it('is failed when the wallet has an identity but no usable token', async () => {
        mockCall.mockResolvedValue(null);
        await useCapabilityAsksStore.getState().refresh();
        expect(useCapabilityAsksStore.getState().loadFailed).toBe(true);
        expect(mockCall.mock.calls[0][1]).toMatchObject({ interactive: false });
    });

    it('is not failed for a wallet with no privasys.id identity', async () => {
        mockHasIdentity.mockReturnValue(false);
        mockCall.mockResolvedValue(null);
        await useCapabilityAsksStore.getState().refresh();
        expect(useCapabilityAsksStore.getState().loadFailed).toBe(false);
    });

    it('is failed on an error answer or no network, and keeps what it had', async () => {
        const expires_at = Math.floor(Date.now() / 1000) + 600;
        mockCall.mockResolvedValueOnce(ok({ pending: [{ nonce: 'n', app_host: 'a.example', expires_at }] }));
        await useCapabilityAsksStore.getState().refresh();
        mockCall.mockResolvedValueOnce({ res: { ok: false, status: 502 }, token: 't' });
        await useCapabilityAsksStore.getState().refresh();
        expect(useCapabilityAsksStore.getState().loadFailed).toBe(true);
        expect(useCapabilityAsksStore.getState().asks).toHaveLength(1);
        mockCall.mockRejectedValueOnce(new Error('offline'));
        await useCapabilityAsksStore.getState().refresh();
        expect(useCapabilityAsksStore.getState().loadFailed).toBe(true);
    });

    it('Try again loads interactively and clears the failure', async () => {
        mockCall.mockResolvedValueOnce(null);
        await useCapabilityAsksStore.getState().refresh();
        mockCall.mockResolvedValueOnce(ok({ pending: [] }));
        await useCapabilityAsksStore.getState().refresh({ interactive: true });
        expect(mockCall.mock.calls[1][1]).toMatchObject({ interactive: true });
        expect(useCapabilityAsksStore.getState().loadFailed).toBe(false);
    });
});

describe('oneLoadAtATime', () => {
    it('joins a background load already running', async () => {
        let release!: () => void;
        const load = jest.fn(() => new Promise<void>((r) => (release = r)));
        const refresh = oneLoadAtATime(load);
        const a = refresh();
        const b = refresh();
        await Promise.resolve();
        release();
        await Promise.all([a, b]);
        expect(load).toHaveBeenCalledTimes(1);
    });

    it('runs an interactive load after the running one, not instead of it', async () => {
        const order: string[] = [];
        let release!: () => void;
        const load = jest.fn((interactive: boolean) => {
            order.push(interactive ? 'interactive' : 'background');
            return interactive ? Promise.resolve() : new Promise<void>((r) => (release = r));
        });
        const refresh = oneLoadAtATime(load);
        const a = refresh();
        const b = refresh({ interactive: true });
        await Promise.resolve();
        release();
        await Promise.all([a, b]);
        expect(order).toEqual(['background', 'interactive']);
        // Free again afterwards.
        await refresh({ interactive: true });
        expect(load).toHaveBeenCalledTimes(3);
    });
});
