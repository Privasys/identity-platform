// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A cached platform token whose session privasys.id ended (signed out from
 * another device) is refused with 401 for the rest of its year. In 1.4.79 the
 * wallet kept sending it: Access listed nothing and every Accept failed as
 * "could not be reached". The token must be dropped, and a tap must mint a
 * new one and go through.
 */

const mockStore = new Map<string, string>();
jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async (k: string) => mockStore.get(k) ?? null),
    setItemAsync: jest.fn(async (k: string, v: string) => void mockStore.set(k, v)),
    deleteItemAsync: jest.fn(async (k: string) => void mockStore.delete(k)),
}));
jest.mock('@/services/demo/gate', () => ({ isDemo: () => false }));
const mockCredential = { credentialId: 'cred-1', keyAlias: 'k', serverRpId: 'privasys.id' };
jest.mock('@/stores/auth', () => ({
    useAuthStore: { getState: () => ({ getCredentialForRp: () => mockCredential, privasysId: null }) },
}));
const mockAuthenticate = jest.fn(async () => ({ sessionToken: 'wallet-session' }));
jest.mock('../services/fido2', () => ({ authenticate: (...a: unknown[]) => mockAuthenticate(...(a as [])) }));
jest.mock('../services/privasys-id', () => ({ ensurePrivasysSession: jest.fn() }));

import { callWithPlatformToken, dropPlatformToken } from '../services/platform-token';

const KEY = 'privasys.platform-token';
const cache = (token: string) =>
    mockStore.set(KEY, JSON.stringify({ token, expiresAt: Date.now() + 300 * 864e5, audience: 'privasys-platform', mintedBy: 'cred-1' }));
const response = (status: number) => ({ status, ok: status < 300 }) as Response;

let minted = 0;
beforeEach(() => {
    mockStore.clear();
    minted = 0;
    mockAuthenticate.mockClear();
    global.fetch = jest.fn(async () => {
        minted++;
        return { ok: true, status: 200, json: async () => ({ token: `fresh-${minted}`, expires_at: Math.floor(Date.now() / 1000) + 365 * 86400 }) };
    }) as unknown as typeof fetch;
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
});

describe('callWithPlatformToken', () => {
    it('uses the cached token while privasys.id accepts it', async () => {
        cache('old');
        const call = jest.fn(async () => response(200));
        const out = await callWithPlatformToken(call, { interactive: true });
        expect(call).toHaveBeenCalledWith('old');
        expect(out?.token).toBe('old');
        expect(minted).toBe(0);
    });

    it('on a tap, replaces a refused token and makes the call once more', async () => {
        cache('old');
        const call = jest.fn(async (t: string) => response(t === 'old' ? 401 : 200));
        const out = await callWithPlatformToken(call, { interactive: true });
        expect(call.mock.calls.map((c) => c[0])).toEqual(['old', 'fresh-1']);
        expect(out?.res.status).toBe(200);
        expect(out?.token).toBe('fresh-1');
        expect(JSON.parse(mockStore.get(KEY)!).token).toBe('fresh-1');
        expect(mockAuthenticate).toHaveBeenCalledTimes(1);
    });

    it('in the background, drops a refused token without prompting', async () => {
        cache('old');
        const call = jest.fn(async () => response(401));
        expect(await callWithPlatformToken(call, { interactive: false })).toBeNull();
        expect(mockStore.has(KEY)).toBe(false);
        expect(mockAuthenticate).not.toHaveBeenCalled();
        // And with nothing cached the background makes no call at all.
        expect(await callWithPlatformToken(call, { interactive: false })).toBeNull();
        expect(call).toHaveBeenCalledTimes(1);
    });

    it('retries once only', async () => {
        cache('old');
        const call = jest.fn(async () => response(401));
        const out = await callWithPlatformToken(call, { interactive: true });
        expect(call).toHaveBeenCalledTimes(2);
        expect(out?.res.status).toBe(401);
    });
});

describe('dropPlatformToken', () => {
    it('never drops a token minted since the refused one', async () => {
        cache('newer');
        await dropPlatformToken('old');
        expect(JSON.parse(mockStore.get(KEY)!).token).toBe('newer');
    });
});
