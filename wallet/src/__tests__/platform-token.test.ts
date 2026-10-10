// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Each service is called with the key that names the holder as that service
 * knows them: Drive's own key at Drive (minted for Drive's client), the
 * platform key everywhere else. The two are cached apart.
 */

jest.mock('@/utils/storage', () => {
    const mockStore: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (k: string) => mockStore[k] ?? null),
        setItemAsync: jest.fn(async (k: string, v: string) => {
            mockStore[k] = v;
        }),
        deleteItemAsync: jest.fn(async (k: string) => {
            delete mockStore[k];
        }),
    };
});
jest.mock('@/services/fido2', () => ({ authenticate: jest.fn(async () => ({ sessionToken: 'sess' })) }));
jest.mock('@/services/privasys-id', () => ({ ensurePrivasysSession: jest.fn(async () => ({ sessionToken: 'sess' })) }));

import { rememberDriveHost, tokenForHost } from '@/services/platform-token';
import { useAuthStore } from '@/stores/auth';

const bodies: any[] = [];
beforeAll(() => {
    useAuthStore.setState({
        credentials: [
            {
                credentialId: 'c1', rpId: 'privasys.id', origin: 'privasys.id', keyAlias: 'k',
                userHandle: 'h', userName: 'n', registeredAt: 1,
            },
        ],
    } as any);
    (global as any).fetch = jest.fn(async (_url: string, init: any) => {
        const body = JSON.parse(init.body);
        bodies.push(body);
        return {
            ok: true,
            json: async () => ({ token: body.client_id ? 'drive-key' : 'platform-key', expires_at: Math.floor(Date.now() / 1000) + 30 * 86400 }),
        };
    });
});

it('gives Drive its own key and everyone else the platform key', async () => {
    await rememberDriveHost('drive.example');
    expect(await tokenForHost('drive.example')).toBe('drive-key');
    expect(await tokenForHost('mail.example')).toBe('platform-key');
    expect(bodies.find((b) => b.client_id)?.client_id).toBe('privasys-drive');
    // Cached apart: asking again mints nothing new.
    const minted = bodies.length;
    expect(await tokenForHost('drive.example')).toBe('drive-key');
    expect(await tokenForHost('mail.example')).toBe('platform-key');
    expect(bodies.length).toBe(minted);
});
